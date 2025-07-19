/*
===============================================================================
    librex-ast - A PCRE2-Compatible Regex Engine

    Author: Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
    Date: July 19, 2025
    License: MIT

    Description:
    ------------
    This file is part of a high-performance, feature-rich, and PCRE2-compatible
    regular expression engine written in C. The library implements both a
    sophisticated parser and a bytecode execution engine (virtual machine) to
    provide a complete compile-and-match solution. It is designed for
    portability, performance, and API clarity, with extensive support for
    modern regex features including Unicode properties, advanced grouping,
    and recursive patterns.

    Key Architectural Features:
    ---------------------------
    - Two-Stage Compilation:
      1. A recursive descent parser builds a detailed Abstract Syntax Tree (AST)
         from the regex pattern.
      2. An AST-to-bytecode compiler translates the tree into a linear, compact
         instruction set for the VM.
    - NFA-based Virtual Machine (VM):
      * A custom VM executes the compiled bytecode to perform the match.
      * Implements a thread-based, backtracking NFA algorithm.
      * Uses a "visited" set for memoization to prevent redundant work and handle
        complex patterns with overlapping subproblems efficiently.
    - Pluggable Memory Management:
      * Core API supports custom allocators ('malloc', 'realloc', 'free'),
        allowing integration into projects with specific memory strategies.
      * The parser uses an internal arena allocator for efficient AST node
        management during compilation.
    - Comprehensive PCRE2 Compatibility:
      * Supports a wide array of advanced constructs found in PCRE2 and Perl.
      * Passes an extensive test suite covering syntax, matching, edge cases,
        and error conditions.
    - Detailed Error Reporting:
      * Provides structured error objects with error codes, messages, and the
        exact line/column number of the error in the pattern.
    - Unicode-Awareness:
      * Full UTF-8 support in both the parser and the matching engine.
      * Built-in support for Unicode property matching (\p, \P) using efficient
        bitmaps.

    Implementation Details:
    -----------------------
    - Parser:
      * Recursive descent with two-phase fixup for resolving forward references
        (e.g., '\k<name>' before '(?<name>...)').
      * Detailed tracking of parser state, including capture counts, named groups,
        and inline flag modifiers.
      * Semantic validation, including fixed-width checks for lookbehind assertions.
    - AST-to-Bytecode Compiler:
      * Translates the AST into a simple and efficient instruction set (e.g.,
        CHAR, ANY, SPLIT, JMP, SAVE, CALL).
      * Capturing groups are compiled into callable subroutines.
    - NFA Virtual Machine (VM):
      * The core matching logic is a loop processing VM instructions.
      * Backtracking is managed by pushing alternative execution paths (threads)
        onto a stack.
      * Instructions for advanced features like atomic groups ('I_MARK_ATOMIC',
        'I_CUT_TO_MARK'), conditionals ('I_GCOND'), and assertions ('I_ACOND', 'I_LBCOND').
    - Unicode:
      * Safe, single-pass UTF-8 decoding.
      * Unicode property matching uses pre-computed range data to build bitmaps,
        which are cached in the AST arena for performance.
      * Unified character class builder handles standard classes ('[a-z]'),
        shorthands ('\d', '\w'), and POSIX classes ('[[:digit:]]') in a
        Unicode-aware manner.
    - API:
      * Clean, two-stage API ('regex_compile', 'regex_match', 'regex_free').
      * Opaque 'regex_compiled*' handle encapsulates the compiled pattern.
      * Match results are returned in a structured, easy-to-use format.

    Supported Regex Constructs:
    ---------------------------
    Basic Elements:
    - Literal characters (full Unicode support)
    - Character classes '[abc]', '[^abc]', '[a-z]'
    - Predefined classes: '\d', '\D', '\w', '\W', '\s', '\S'
    - Dot metacharacter '.' (respects single-line mode)
    - Anchors: '^', '$', '\A', '\z', '\b', '\B'

    Quantifiers:
    - Greedy: '*', '+', '?', '{n}', '{n,}', '{n,m}'
    - Lazy (Non-greedy): '*?', '+?', '??', '{n,m}?'
    - Possessive: '*+', '++', '?+', '{n,m}+'

    Groups:
    - Capturing groups: '(...)'
    - Non-capturing groups: '(?:...)'
    - Named groups: '(?<name>...)', '(?'name'...)'
    - Atomic groups: '(?>...)'
    - Branch-reset groups: '(?|...)'

    Assertions:
    - Positive lookahead: '(?=...)'
    - Negative lookahead: '(?!...)'
    - Positive lookbehind: '(?<=...)'
    - Negative lookbehind: '(?<!...)'

    Backreferences:
    - Numbered: '\1', '\2', etc.
    - Named: '\k<name>', '\k'name''

    Conditionals:
    - By group number: '(?(1)yes|no)'
    - By group name: '(?(<name>)yes|no)'
    - By assertion: '(?(?=...)yes|no)'

    Subroutines:
    - Full pattern recursion: '(?R)'
    - By group number: '(?1)', '(?2)', etc.
    - By group name: '(?&name)'

    Modifiers & Comments:
    - Inline flags: '(?i)', '(?-m)', etc.
    - Scoped flags: '(?i:...)'
    - Comments: '(?#...)'

    Unicode & Escapes:
    - UTF-8 input processing and validation.
    - Unicode properties: '\p{L}', '\P{Sc}', etc.
    - Hex escapes: '\x20', '\x{1F600}'
    - Quoted sequences: '\Q...\E'
    - POSIX character classes: '[[:alpha:]]', '[[:digit:]]', etc.

    Current Limitations:
    --------------------
    - No AST or bytecode optimization passes are currently performed.
    - Lookbehind assertions must be fixed-length (variable-length lookbehind is not supported).
    - Maximum lookbehind length is 255 characters (PCRE2 compatible).
    - No support for '\g{...}' backreference/subroutine syntax (use '\k<>', '(?n)' instead).
    - No support for script runs or grapheme clusters ('\X').
    - No support for generic newline sequences ('\R').
    - No support for control verbs like '(*SKIP)', '(*FAIL)', '(*ACCEPT)'.
    - No support for callouts.
===============================================================================
*/

#include "regex-parser.h"
#include "regex-unicode.h"
#include "regex-internals.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#ifdef _MSC_VER
#include <malloc.h> // For _alloca
#define alloca _alloca
#endif

typedef struct {
    Instr *code;
    size_t pc, capsize;
    size_t maxpc;
    const regex_allocator *alloc;
    SubroutineTable subroutines;
    size_t *group_starts;  // Track where each group starts
    int max_groups;
    AstArena* arena; 
    bool oom;  // Error flag for out-of-memory conditions
} CodeBuf;


typedef struct {
    uint8_t *bits;
    size_t   pcs;          /* number of instructions          */
    size_t   span;         /* subject_len + 1                 */
} Visited;

static inline int seen(Visited *v, size_t pc, size_t idx)
{
    /* sentinel or invalid addresses are never entered twice
       in a way that matters for back‑tracking, so skip them. */
    if (pc >= v->pcs)            /* <‑‑ guard against SIZE_MAX */
        return 0;

    size_t key  = pc * v->span + idx;
    size_t byte = key >> 3, mask = ((size_t)1u) << (key & 7);
    if (v->bits[byte] & mask) return 1;   /* already processed */
    v->bits[byte] |= mask;
    return 0;
}

#define CASELESS_BIT   (((uintptr_t)1U) << (sizeof(uintptr_t)*8-1))

static void emit(CodeBuf *b, Instr i) {
    if (b->oom) return;  // Already in error state
    
    if (b->pc >= b->maxpc) {
        size_t n = b->maxpc ? b->maxpc * 2 : 128;
        Instr *t = b->alloc->realloc_func(b->code, n * sizeof(Instr),
                                          b->alloc->user_data);
        if (!t) {
            b->oom = true;  // Set error flag
            return;
        }
        b->code = t;
        b->maxpc = n;
    }
    b->code[b->pc++] = i;
}

static void init_codebuf_subroutines(CodeBuf *b, int max_groups) {
    b->subroutines.defs = NULL;
    b->subroutines.count = 0;
    b->subroutines.capacity = 0;
    b->max_groups = max_groups;
    b->oom = false;  // Initialize error flag
    
    b->group_starts = b->alloc->malloc_func((max_groups + 1) * sizeof(size_t), b->alloc->user_data);
    if (!b->group_starts) {
        b->oom = true;
        return;
    }
    for (int i = 0; i <= max_groups; i++) {
        b->group_starts[i] = SIZE_MAX;
    }
}

static void cleanup_codebuf_subroutines(CodeBuf *b) {
    for (int i = 0; i < b->subroutines.count; i++) {
        if (b->subroutines.defs[i].group_name) {
            b->alloc->free_func(b->subroutines.defs[i].group_name, b->alloc->user_data);
        }
    }
    if (b->subroutines.defs) {
        b->alloc->free_func(b->subroutines.defs, b->alloc->user_data);
    }
    if (b->group_starts) {
        b->alloc->free_func(b->group_starts, b->alloc->user_data);
    }
}

static size_t find_subroutine_pc(CodeBuf *b, int group_index, char *group_name) {
    // First check named groups
    if (group_name) {
        for (int i = 0; i < b->subroutines.count; i++) {
            SubroutineDef *def = &b->subroutines.defs[i];
            if (def->group_name && strcmp(def->group_name, group_name) == 0) {
                return def->start_pc;
            }
        }
    }
    // Then check numbered groups
    if (group_index > 0 && group_index <= b->max_groups) {
        return b->group_starts[group_index];
    }
    return SIZE_MAX;
}

static size_t compile_node(CodeBuf *b, RegexNode *n, bool ignorecase, bool dot_nl, bool multiline);

static size_t placeholder(CodeBuf *b) {
    emit(b, (Instr){.op = I_JMP, .x = 0});
    return b->pc - 1;
}
static void patch(CodeBuf *b, size_t addr, size_t target) {
    if (b->oom) return;  // Don't patch if in error state
    if (addr < b->pc) {  // Bounds check
        b->code[addr].x = (int32_t)target;
    }
}

int compute_width(RegexNode *node, int *min, int *max);

static void record_group_start(CodeBuf *b, int group_index, const char *group_name, size_t pc) {
    if (b->oom) return;  // Already in error state
    
    if (group_index > 0 && group_index <= b->max_groups) {
        b->group_starts[group_index] = pc;
    }
    
    // Also record named groups
    if (group_name) {
        if (b->subroutines.count >= b->subroutines.capacity) {
            int new_capacity = b->subroutines.capacity > 0 ? b->subroutines.capacity * 2 : 8;
            // Use temporary pointer to avoid corrupting state on failure
            SubroutineDef *new_defs = b->alloc->realloc_func(b->subroutines.defs, 
                new_capacity * sizeof(SubroutineDef), b->alloc->user_data);
            if (!new_defs) {
                b->oom = true;
                return;
            }
            b->subroutines.defs = new_defs;
            b->subroutines.capacity = new_capacity;
        }
        
        SubroutineDef *def = &b->subroutines.defs[b->subroutines.count++];
        def->group_index = group_index;
        
        // Instead of using strdup, we use an allocator-based implementation
        size_t name_len = strlen(group_name) + 1;
        def->group_name = b->alloc->malloc_func(name_len, b->alloc->user_data);
        if (!def->group_name) {
            b->oom = true;
            b->subroutines.count--;  // Roll back the count increment
            return;
        }
        memcpy(def->group_name, group_name, name_len);
        def->start_pc = pc;
    }
}

static inline bool flags_group_affects_following(const RegexNode *n)
{
    return (n && (n->type == REGEX_NODE_GROUP || n->type == REGEX_NODE_BRESET_GROUP)
            && n->data.group.child == NULL);
}

/* ------------------------------------------------------------------ */
/*  Return the value of the ignore‑case flag after executing the  */
/*  subtree n.  ic_before is the flag value on entry.             */
/* ------------------------------------------------------------------ */
static bool ic_after_node(const RegexNode *n, bool ic_before)
{
    if (!n) return ic_before;

    switch (n->type) {

        /* flag‑only or flag‑scoped groups                              */
        case REGEX_NODE_GROUP:
        case REGEX_NODE_BRESET_GROUP:
            /* exit_flags is the mode in force **after** the group      */
            if (n->data.group.child == NULL)          /* (?i)          */
                return (n->data.group.exit_flags & REG_IGNORECASE) != 0;

            /* ordinary group – flags inside do not leak out            */
            return ic_before;

        /* concatenation: evaluate left then right                      */
        case REGEX_NODE_CONCAT:
            return ic_after_node(
                       n->data.children.right,
                       ic_after_node(n->data.children.left, ic_before));

        default:
            return ic_before;      /* all other nodes do not change it */
    }
}


// Forward declarations for compile functions
static size_t compile_assertion(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline);
static size_t compile_conditional(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline);
static size_t compile_char(CodeBuf *b, RegexNode *n, bool ic);
static size_t compile_dot(CodeBuf *b, RegexNode *n, bool dotnl);
static size_t compile_anchor(CodeBuf *b, RegexNode *n, bool multiline);
static size_t compile_char_class(CodeBuf *b, RegexNode *n);
static size_t compile_uni_prop(CodeBuf *b, RegexNode *n);
static size_t compile_concat(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline);
static size_t compile_backref(CodeBuf *b, RegexNode *n, bool ic);
static size_t compile_alternation(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline);
static size_t compile_quantifier(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline);
static size_t compile_subroutine(CodeBuf *b, RegexNode *n);
static size_t compile_group(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline);

static size_t compile_assertion(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline) {
    if (b->oom) return 0;
    
    AssertionType atype = n->data.assertion.assert_type;
    bool is_neg = (atype == ASSERT_LOOKAHEAD_NEG || atype == ASSERT_LOOKBEHIND_NEG);
    uint8_t op = (atype == ASSERT_LOOKAHEAD_POS || atype == ASSERT_LOOKAHEAD_NEG) ? I_ACOND : I_LBCOND;

    // Compute the width for lookbehinds
    int width = 0;
    if (op == I_LBCOND) {
        int min, max;
        compute_width(n->data.assertion.child, &min, &max);
        if (min != max || max == -1) {
            // This should have been caught during parsing, but ensure safety
            return 0; // Invalid lookbehind
        }
        width = min; // Fixed length
    }

    // Jump over the assertion's sub-pattern
    size_t jmp_over_assert = placeholder(b);

    // Compile the assertion's sub-pattern
    size_t assert_sub_pc = b->pc;
    compile_node(b, n->data.assertion.child, ic, dotnl, multiline);
    emit(b, (Instr){.op = I_ASUCCESS}); // Mark end of successful probe

    // Patch the jump to skip the sub-pattern
    patch(b, jmp_over_assert, b->pc);

    // Emit the assertion instruction
    emit(b, (Instr){
        .op = op,
        .val = is_neg,
        .x = (int32_t)assert_sub_pc,
        .y = (int32_t)width // For I_LBCOND, store the width; for I_ACOND, y is 0
    });

    return 0;
}

static size_t compile_conditional(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline) {
    if (b->oom) return 0;
    
    Condition *c = &n->data.conditional.cond;

    if (c->type == COND_NUMERIC) {
        size_t gcond_addr = b->pc;
        emit(b, (Instr){.op = I_GCOND, .val = (uintptr_t)c->data.group_index, .x = 0, .y = 0});

        // "yes" branch
        size_t yes_start = b->pc;
        compile_node(b, n->data.conditional.if_true, ic, dotnl, multiline);

        // Jump over the "no" branch
        size_t jmp_over_no = placeholder(b);

        // "no" branch
        size_t no_start = b->pc;
        if (n->data.conditional.if_false)
            compile_node(b, n->data.conditional.if_false, ic, dotnl, multiline);

        // Patch addresses
        b->code[gcond_addr].x = (int32_t)yes_start;
        b->code[gcond_addr].y = (int32_t)no_start;
        patch(b, jmp_over_no, b->pc);
        return 0;
    }

    if (c->type == COND_ASSERTION) { // Handle assertion-based conditions
        RegexNode *assert_node = c->data.assertion;
        AssertionType atype = assert_node->data.assertion.assert_type;
        bool is_neg = (atype == ASSERT_LOOKAHEAD_NEG || atype == ASSERT_LOOKBEHIND_NEG);
        uint8_t op = (atype == ASSERT_LOOKAHEAD_POS || atype == ASSERT_LOOKAHEAD_NEG) ? I_ACOND : I_LBCOND;

        // Compute the width for lookbehinds
        int width = 0;
        if (op == I_LBCOND) {
            int min, max;
            compute_width(assert_node->data.assertion.child, &min, &max);
            if (min != max || max == -1) {
                goto fallback_alternation; // Invalid lookbehind
            }
            width = min;
        }

        // Jump over the assertion's sub-pattern
        size_t jmp_over_assert = placeholder(b);

        // Compile the assertion's sub-pattern
        size_t assert_sub_pc = b->pc;
        compile_node(b, assert_node->data.assertion.child, ic, dotnl, multiline);
        emit(b, (Instr){.op = I_ASUCCESS});

        // Patch the jump
        patch(b, jmp_over_assert, b->pc);

        // Emit the conditional assertion instruction
        size_t cond_addr = b->pc;
        emit(b, (Instr){.op = op, .val = is_neg, .x = (int32_t)assert_sub_pc, .y = (int32_t)width});

        // Compile 'yes' branch
        compile_node(b, n->data.conditional.if_true, ic, dotnl, multiline);

        // Jump over 'no' branch
        size_t jmp_over_no = placeholder(b);

        // Compile 'no' branch
        size_t no_start = b->pc;
        if (n->data.conditional.if_false)
            compile_node(b, n->data.conditional.if_false, ic, dotnl, multiline);

        // Patch the conditional and jump addresses
        if (op == I_ACOND) {
            b->code[cond_addr].y = (int32_t)no_start;
        }
        patch(b, jmp_over_no, b->pc);
        return 0;
    }

fallback_alternation:;
    // Fallback for unsupported conditions (e.g., named groups)
    size_t split_addr = b->pc;
    emit(b, (Instr){.op = I_SPLIT, .x = 0, .y = 0});

    // "Yes" branch (left side of alternation)
    size_t left_start = b->pc;
    compile_node(b, n->data.conditional.if_true, ic, dotnl, multiline);
    size_t jmp_addr = placeholder(b);

    // "No" branch (right side of alternation)
    size_t right_start = b->pc;
    if (n->data.conditional.if_false) {
         compile_node(b, n->data.conditional.if_false, ic, dotnl, multiline);
    }

    // Patch the SPLIT instruction
    b->code[split_addr].x = (int32_t)left_start;
    b->code[split_addr].y = (int32_t)right_start;

    // Patch the JMP instruction to jump to the end
    patch(b, jmp_addr, b->pc);

    return 0;
}

static size_t compile_char(CodeBuf *b, RegexNode *n, bool ic) {
    if (b->oom) return 0;
    
    uint32_t c = n->data.codepoint;
    /* fold the pattern character only when ASCII & caseless     */
    bool caseless = ic && c < 128;
    if (caseless) c = (uint32_t)tolower(c);

    emit(b, (Instr){
        .op  = I_CHAR,
        .val = ((uintptr_t)c) | (caseless ? CASELESS_BIT : 0)
    });
    return 1;
}

static size_t compile_dot(CodeBuf *b, RegexNode *n, bool dotnl) {
    (void)n; // Unused parameter
    if (b->oom) return 0;
    
    emit(b, (Instr){.op = I_ANY, .val = dotnl});
    return 1;
}

static size_t compile_anchor(CodeBuf *b, RegexNode *n, bool multiline) {
    if (b->oom) return 0;
    
    uint8_t op = 0;
    switch (n->data.anchor_type) {
        case '^': op = multiline ? I_MBOL : I_BOL; break;
        case '$': op = multiline ? I_MEOL : I_EOL; break;
        case 'b': op = I_BOUND; break;
        case 'B': op = I_NBOUND; break;
        case 'A': op = I_SBOL;   break;
        case 'z': op = I_SEOL;   break;
        default: break;
    }
    if (op != 0) emit(b, (Instr){.op = op});
    return 1;
}

static size_t compile_char_class(CodeBuf *b, RegexNode *n) {
    if (b->oom) return 0;
    
    // Use the unified bitmap builder for all character classes
    uint32_t *ubm = build_class_bitmap(n->data.char_class.set, b->arena);
    if (!ubm) {
        b->oom = true;
        return 0;
    }

    if (n->data.char_class.negated) {
        for (size_t w = 0; w < UNI_BM_WORDS; ++w) {
            ubm[w] = ~ubm[w];
        }
    }
    
    // Always use Unicode property instruction for consistency
    emit(b, (Instr){.op = I_UNIPROP, .val = (uintptr_t)ubm});
    return 1;
}

static size_t compile_uni_prop(CodeBuf *b, RegexNode *n) {
    if (b->oom) return 0;
    
    // Build the bitmap at compile-time using the property name from the AST
    uint32_t *bitmap = build_unicode_property_bitmap(n->data.uni_prop.prop_name, b->arena);
    if (!bitmap) {
        b->oom = true;
        return 0;
    }
    
    // Apply negation if needed
    if (n->data.uni_prop.negated) {
        for (size_t w = 0; w < UNI_BM_WORDS; ++w) {
            bitmap[w] = ~bitmap[w];
        }
    }
    
    // Emit the instruction with the newly created bitmap
    emit(b, (Instr){.op = I_UNIPROP, .val = (uintptr_t)bitmap});
    return 1;
}

static size_t compile_concat(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline) {
    if (b->oom) return 0;
    
    /* compile the left side with the incoming flag state              */
    compile_node(b, n->data.children.left, ic, dotnl, multiline);

    /* work out the flag state that is in force after the left side    */
    bool ic_after = ic_after_node(n->data.children.left, ic);

    /* compile the right side with that state                          */
    compile_node(b, n->data.children.right, ic_after, dotnl, multiline);
    return 0;
}

static size_t compile_backref(CodeBuf *b, RegexNode *n, bool ic) {
    if (b->oom) return 0;
    
    int group_num = n->data.backref.ref_index;
    // stash ic in the .x field
    emit(b, (Instr){ .op = I_BACKREF,
                     .val = (uintptr_t)group_num,
                     .x   = (int32_t)ic });
    return 1;
}

static size_t compile_alternation(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline) {
    if (b->oom) return 0;
    
    size_t split_addr = b->pc;
    emit(b, (Instr){.op = I_SPLIT, .x = 0, .y = 0});
    
    size_t left_start = b->pc;
    compile_node(b, n->data.children.left, ic, dotnl, multiline);
    size_t jmp_addr = placeholder(b);
    
    size_t right_start = b->pc;
    compile_node(b, n->data.children.right, ic, dotnl, multiline);
    
    b->code[split_addr].x = (int32_t)left_start;
    b->code[split_addr].y = (int32_t)right_start;
    
    patch(b, jmp_addr, b->pc);
    
    return 0;
}

static size_t compile_quantifier(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline) {
    if (b->oom) return 0;
    
    int m = n->data.quantifier.min;
    int M = n->data.quantifier.max;

    if (!m && M == 0) return 0;
    if (m == 1 && M == 1) {
        compile_node(b, n->data.quantifier.child, ic, dotnl, multiline);
        return 0;
    }

    // Compile minimum repetitions
    for (int i = 0; i < m; ++i) {
        compile_node(b, n->data.quantifier.child, ic, dotnl, multiline);
    }

    // Handle optional repetitions
    if (M < 0) { // * or +
        size_t loop_start = b->pc;
        emit(b, (Instr){.op = I_SPLIT, .x = 0, .y = 0});
        size_t body_start = b->pc;
        compile_node(b, n->data.quantifier.child, ic, dotnl, multiline);
        emit(b, (Instr){.op = I_JMP, .x = (int32_t)loop_start});

        // For lazy quantifiers, prefer the exit path
        if (n->data.quantifier.quant_type == QUANT_LAZY) {
            b->code[loop_start].x = (int32_t)b->pc;      // exit first
            b->code[loop_start].y = (int32_t)body_start; // loop second
        } else { // QUANT_GREEDY
            b->code[loop_start].x = (int32_t)body_start; // loop first
            b->code[loop_start].y = (int32_t)b->pc;      // exit second
        }
    } else if (M > m) { // Fixed upper bound
        for (int i = m; i < M; ++i) {
            size_t split_addr = b->pc;
            emit(b, (Instr){.op = I_SPLIT, .x = 0, .y = 0});
            size_t body_start = b->pc;
            compile_node(b, n->data.quantifier.child, ic, dotnl, multiline);
    
            if (n->data.quantifier.quant_type == QUANT_LAZY) {
                b->code[split_addr].x = (int32_t)b->pc;      // skip first
                b->code[split_addr].y = (int32_t)body_start; // match second
            } else {
                b->code[split_addr].x = (int32_t)body_start; // match first
                b->code[split_addr].y = (int32_t)b->pc;      // skip second
            }
        }
    }
    return 0;
}

static size_t compile_subroutine(CodeBuf *b, RegexNode *n) {
    if (b->oom) return 0;
    
    size_t target_pc;
    if (n->data.subroutine.is_recursion) {
        // (?R) - call the entire pattern (group 0)
        target_pc = 0;
    } else {
        target_pc = find_subroutine_pc(b, 
            n->data.subroutine.target_index, n->data.subroutine.target_name);
        if (target_pc == SIZE_MAX) {
            // Subroutine not found - emit a no-op for now
            return 0;
        }
    }
    
    emit(b, (Instr){
        .op  = I_CALL,
        .x   = (int32_t)target_pc,
        .val = n->data.subroutine.is_recursion ? 0 : n->data.subroutine.target_index
        });
    return 0;
}

static size_t compile_group(CodeBuf *b, RegexNode *n, bool ic, bool dotnl, bool multiline) {
    if (b->oom) return 0;
    
    /* ------------------------------------------------------------
     * Determine the ignore‑case state that is active *inside* the
     * group.  A flag‑setting group records, during parsing, the
     * flags as they were on entry (`enter_flags`) and the flags
     * as they should be while its body is matched (`exit_flags`).
     * ---------------------------------------------------------- */
    bool child_ic = ic;
    if (n->data.group.enter_flags != n->data.group.exit_flags) {
        child_ic = (n->data.group.exit_flags & REG_IGNORECASE) != 0;
    }
    int idx = n->data.group.capture_index;
    bool is_atomic = n->data.group.is_atomic;

    // Handle all non-capturing groups, including atomic (?>...)
    if (idx <= 0) {
        if (is_atomic) {
            // Atomic groups prevent backtracking within the group
            emit(b, (Instr){.op = I_MARK_ATOMIC});
            compile_node(b, n->data.group.child, child_ic, dotnl, multiline);
            emit(b, (Instr){.op = I_CUT_TO_MARK});
        } else {
            // This is for normal non-capturing groups (?:...) and flag-setting groups (?i:...)
            compile_node(b, n->data.group.child, child_ic, dotnl, multiline);
        }
        return 0;
    }    

    // For capturing groups, we treat them as callable subroutines.
    // First, we emit the subroutine's body, preceded by a jump
    // to skip over it during normal execution.

    // 1. Jump over the subroutine definition.
    size_t jmp_over_sub = placeholder(b);

    // 2. Define the subroutine body, recording its starting PC
    size_t sub_pc = b->pc;
    record_group_start(b, idx, n->data.group.name, sub_pc);

    // Saves are now INSIDE the body
    emit(b, (Instr){.op = I_SAVE, .val = (uintptr_t)(idx * 2)});
    compile_node(b, n->data.group.child, child_ic, dotnl, multiline);
    emit(b, (Instr){.op = I_SAVE, .val = (uintptr_t)(idx * 2 + 1)});

    emit(b, (Instr){.op = I_RETURN});

    // 3. Patch the initial jump to land after the subroutine body.
    patch(b, jmp_over_sub, b->pc);

    // 4. Emit the code for the inline execution of the group:
    //    Just call the subroutine (which now handles captures).
    emit(b, (Instr){.op = I_CALL, .x = (int32_t)sub_pc});
    
    return 0;
}

static size_t compile_node(CodeBuf *b, RegexNode *n, bool ignorecase, bool dot_nl, bool multiline) {
    if (!n || b->oom) return 0;
    
    switch (n->type) {
        case REGEX_NODE_ASSERTION:
            return compile_assertion(b, n, ignorecase, dot_nl, multiline);
        case REGEX_NODE_CONDITIONAL:
            return compile_conditional(b, n, ignorecase, dot_nl, multiline);
        case REGEX_NODE_CHAR:
            return compile_char(b, n, ignorecase);
        case REGEX_NODE_DOT:
            return compile_dot(b, n, dot_nl);
        case REGEX_NODE_ANCHOR:
            return compile_anchor(b, n, multiline);
        case REGEX_NODE_CHAR_CLASS:
            return compile_char_class(b, n);
        case REGEX_NODE_UNI_PROP:
            return compile_uni_prop(b, n);
        case REGEX_NODE_CONCAT:
            return compile_concat(b, n, ignorecase, dot_nl, multiline);
        case REGEX_NODE_BACKREF:
            return compile_backref(b, n, ignorecase);
        case REGEX_NODE_ALTERNATION:
            return compile_alternation(b, n, ignorecase, dot_nl, multiline);
        case REGEX_NODE_QUANTIFIER:
            return compile_quantifier(b, n, ignorecase, dot_nl, multiline);
        case REGEX_NODE_SUBROUTINE:
            return compile_subroutine(b, n);
        case REGEX_NODE_BRESET_GROUP:
        case REGEX_NODE_GROUP:
            return compile_group(b, n, ignorecase, dot_nl, multiline);
        default:
            break;
    }
    return 0;
}

static size_t advance_linenl(const uint8_t *s, size_t n, size_t i, bool multiline,
                             bool *bol, bool *eol) {
    *bol = (i == 0);
    *eol = (i == n);
    if (i == 0) return i;
    uint8_t c = s[i-1];
    *bol = multiline && (c == '\n' || (i > 1 && c == '\n' && s[i-2] == '\r'));
    *eol = (i == n) || (multiline && (s[i] == '\n' || (i + 1 < n && s[i] == '\r' && s[i+1] == '\n')));
    return i;
}

/* simple thread based backtrack VM */
typedef struct {
    size_t return_pc;     // where to return after the call
    int target_group;     // if nonzero, the capturing group that is being called
    size_t saved_start;   // saved capture start position for that group
    size_t saved_end;     // saved capture end position for that group
} CallEntry;

#define MAX_CALL_DEPTH 32

typedef struct { 
    size_t pc, idx; 
    size_t *caps;
    size_t cap_size;
    CallEntry call_stack[MAX_CALL_DEPTH];  // Add call stack
    int call_depth;                     // Add call depth
} Thread;

typedef struct { Thread *data; size_t cap, len; } Threads;


// This function is for creating the very first thread of execution.
static Thread make_thread_initial(size_t pc, size_t idx, size_t cap_size) {
    Thread t;
    t.pc = pc;
    t.idx = idx;
    t.cap_size = cap_size;
    // Initialize capture array
    t.call_depth = 0;  // A new thread has no call history.
    t.caps = malloc(cap_size * sizeof(size_t));
    if (t.caps) {
        // Initialize captures to "not set"
        for (size_t i = 0; i < cap_size; i++) t.caps[i] = SIZE_MAX;
    }
    return t;
}

// This function clones an existing thread, preserving its full state (captures and call stack),
// and gives the clone a new program counter and string index.
static Thread clone_thread(const Thread *src, size_t new_pc, size_t new_idx) {
    Thread t;
    t.pc = new_pc;
    t.idx = new_idx;
    t.cap_size = src->cap_size;
    t.call_depth = src->call_depth; // Preserve call stack depth
    // Clone capture array
    t.caps = malloc(src->cap_size * sizeof(size_t));
    if (t.caps) {
        memcpy(t.caps, src->caps, src->cap_size * sizeof(size_t));
        // Preserve call stack content
        memcpy(t.call_stack, src->call_stack, src->call_depth * sizeof(CallEntry));
    }
    return t;
}


static void free_thread(Thread *t) {
    if (t->caps) {
        free(t->caps);
        t->caps = NULL;
    }
}

static void push(Threads *q, Thread t, Visited *v)
{
    if (seen(v, t.pc, t.idx)) {    /* global duplicate? */
        free_thread(&t);
        return;
    }
    /* drop the thread if we already have pc+idx in the queue */
    for (size_t i = 0; i < q->len; ++i) {
        if (q->data[i].pc == t.pc && q->data[i].idx == t.idx) {
            free_thread(&t);          /* capture state is redundant too */
            return;
        }
    }

    /* grow the queue if necessary */
    if (q->len >= q->cap) {
        size_t n = q->cap ? q->cap * 2 : 128;
        Thread *x = realloc(q->data, n * sizeof(Thread));   /* local alloc OK */
        if (!x) { free_thread(&t); return; }
        q->data = x;
        q->cap  = n;
    }
    q->data[q->len++] = t;
}

static Thread pop(Threads *q) {
    return q->data[--q->len];
}

static int run_vm_engine(
    const Instr *code, size_t pcs,
    const uint8_t *s, size_t n, int capture,
    int *starts, int *ends, // NULL in probe mode
    Threads *q,
    Visited *v,            // visited state
    // is_probe indicates if this is a sub-match for assertions
    bool is_probe
);

static int run_vm(const Instr *code, size_t pcs,
                  const uint8_t *s, size_t n, int capture,
                  int *starts, int *ends, size_t initial_idx) {
    size_t cap_size = 2 * (capture + 1);
    
    Threads stack = {0};
    
    // Use the new function for creating the initial thread
    Thread initial = make_thread_initial(0, initial_idx, cap_size);
    if (!initial.caps) return -REGEX_ERR_MEMORY;  // Return negative error code
    
    Visited vis = {0};
    vis.pcs   = pcs;
    vis.span  = n + 1;
    
    // Check for overflow in visited set sizing
    if (pcs > 0 && vis.span > SIZE_MAX / pcs) {
        free_thread(&initial);
        return -REGEX_ERR_MEMORY;  // Return negative error code
    }
    
    size_t bytes = ((pcs * vis.span) + 7) >> 3;
    vis.bits  = calloc(bytes, 1);
    if (!vis.bits) { 
        free_thread(&initial); 
        return -REGEX_ERR_MEMORY;  // Return negative error code
    }

    push(&stack, initial, &vis);          /* pass vis to push() */
    
    int ret = run_vm_engine(code, pcs, s, n, capture,
                            starts, ends, &stack, &vis, false);
    
    // Cleanup any remaining threads on the main stack
    while (stack.len > 0) {
        Thread t = pop(&stack);
        free_thread(&t);
    }
    free(stack.data);
    free(vis.bits);
    
    return ret;  // Return the actual result (1 for match, 0 for no match, negative for error)
}

static int run_vm_engine(
    const Instr *code, size_t pcs,
    const uint8_t *s, size_t n, int capture,
    int *starts, int *ends,
    // probe_q is the thread queue for assertion sub-matches
    Threads *q,
     Visited *v,
    bool is_probe
) {
    while (q->len > 0) {
        Thread t = pop(q);
        
        // Handle atomic group markers
        if (t.pc == SIZE_MAX) {
            // It's a marker. It has no allocated `caps`. Just discard and continue.
            continue; // Marker thread for atomic groups
        }

        if (t.pc >= pcs) { // Invalid PC, discard thread
            free_thread(&t);
            continue;
        }
        
        const Instr *I = &code[t.pc];

        // Check for probe success
        if (is_probe && I->op == I_ASUCCESS) {
            // Successful assertion probe
            free_thread(&t);
            return 1; // Probe success
        }

        // Check for main match success
        if (!is_probe && I->op == I_MATCH) {
            // Successful match found, record captures if provided
            if (starts && ends) {
                for (int c = 0; c <= capture; c++) {
                    size_t start_idx = c * 2;
                    size_t end_idx = c * 2 + 1;
                    starts[c] = (start_idx < t.cap_size && t.caps[start_idx] != SIZE_MAX) ? (int)t.caps[start_idx] : -1;
                    ends[c] = (end_idx < t.cap_size && t.caps[end_idx] != SIZE_MAX) ? (int)t.caps[end_idx] : -1;
                }
            }
            free_thread(&t);
            return 1; // Match success
        }

        switch (I->op) {
            case I_SEOL: {                       /* strict end‑of‑subject (\z) */
                if (t.idx == n) {                /* only at absolute end       */
                    Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                    if (nt.caps) push(q, nt, v);
                }
                free_thread(&t);
                break;
            }
            case I_MARK_ATOMIC: {
                // Push atomic group marker
                // Push a special marker thread. It has a special PC and no allocated caps.
                Thread marker = { .pc = SIZE_MAX, .idx = 0, .caps = NULL, .cap_size = 0, .call_depth = 0 };
                push(q, marker, v);

                // Continue execution of the current thread.
                Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                if (nt.caps) push(q, nt, v);

                free_thread(&t);
                break;
            }
            case I_CUT_TO_MARK: {
                // Commit to successful atomic group path, discard alternatives
                // A thread made it through an atomic group.
                // Pop all alternative threads that were created inside the group.
                while (q->len > 0) {
                    Thread top = pop(q);
                    if (top.pc == SIZE_MAX) { // Found marker
                        // Marker has no caps, so no need to free.
                        break;
                    }
                    free_thread(&top);
                }
                
                // Continue with the current successful thread.
                Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                if (nt.caps) push(q, nt, v);
                free_thread(&t);
                break;
            }
            case I_CALL: { // Handle subroutine calls
                size_t target_pc = (size_t)I->x;
                int target_group = (int)I->val;  // nonzero if this call is a subroutine call to a capturing group
                if (t.call_depth >= MAX_CALL_DEPTH) {
                    free_thread(&t);
                    return -REGEX_ERR_RECURSION_LIMIT;
                }
                Thread nt = clone_thread(&t, target_pc, t.idx);
                // Save the return address and, if needed, the current capture for the target group.
                if (target_group != 0 && target_group * 2 + 1 < (int) t.cap_size) {
                    nt.call_stack[nt.call_depth].return_pc = t.pc + 1;
                    nt.call_stack[nt.call_depth].target_group = target_group;
                    nt.call_stack[nt.call_depth].saved_start = t.caps[target_group * 2];
                    nt.call_stack[nt.call_depth].saved_end = t.caps[target_group * 2 + 1];
                } else {
                    nt.call_stack[nt.call_depth].return_pc = t.pc + 1;
                    nt.call_stack[nt.call_depth].target_group = 0;
                }
                nt.call_depth++;
                push(q, nt, v);
                free_thread(&t);
                break;
            }

            case I_RETURN: { // Handle return from subroutine
                if (t.call_depth == 0) {
                    // fallback (should not happen)
                    Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                    if (nt.caps) push(q, nt, v);
                    free_thread(&t);
                    break;
                }
                // Pop the call entry
                CallEntry entry = t.call_stack[t.call_depth - 1];
                t.call_depth--;
                // Restore the original capture values if this was a subroutine call to a capturing group.
                if (entry.target_group != 0 && entry.target_group * 2 + 1 < (int) t.cap_size) {
                    t.caps[entry.target_group * 2] = entry.saved_start;
                    t.caps[entry.target_group * 2 + 1] = entry.saved_end;
                }

                Thread nt = clone_thread(&t, entry.return_pc, t.idx);
                if (nt.caps) push(q, nt, v);
                free_thread(&t);
                break;
            }
            case I_GCOND: { // Group condition: check if group has captured
                size_t group_idx = I->val;
                size_t start_idx = group_idx * 2;
                bool cond_met = (start_idx < t.cap_size && t.caps[start_idx] != SIZE_MAX);
                size_t target_pc = cond_met ? (size_t)I->x : (size_t)I->y;
                Thread nt = clone_thread(&t, target_pc, t.idx);
                if (nt.caps) push(q, nt, v);
                free_thread(&t);
                break;
            }
            case I_ACOND: {
                bool is_neg = (bool)I->val;
                size_t sub_pc = (size_t)I->x;
                size_t no_pc = (size_t)I->y;

                // Set up and run the probe match for the assertion
                Threads probe_q = {0};
                // Clone current thread state for probe
                Thread probe_initial = clone_thread(&t, sub_pc, t.idx); // Must clone to preserve call stack
                if (!probe_initial.caps) { free_thread(&t); break; }
                push(&probe_q, probe_initial, v);

                int probe_res = run_vm_engine(code, pcs, s, n, capture, NULL, NULL, &probe_q, v, true);

                while (probe_q.len > 0) { 
                    Thread to_free = pop(&probe_q);
                    free_thread(&to_free);
                }
                free(probe_q.data);

                bool sub_matched = (probe_res == 1);
                bool assert_holds = (sub_matched != is_neg);
                size_t target_pc;
                if (I->y == 0) {  // pure assertion
                    if (assert_holds) {
                        target_pc = t.pc + 1;
                    } else {
                        target_pc = (size_t)-1;  // sentinel to discard
                    }
                } else {  // conditional
                    target_pc = assert_holds ? t.pc + 1 : no_pc;
                }
                if (target_pc != (size_t)-1) {
                    Thread nt = clone_thread(&t, target_pc, t.idx);
                    if (nt.caps) push(q, nt, v);
                }
                free_thread(&t);
                break;
            }
            case I_LBCOND: {
                bool is_neg = (bool)I->val;
                size_t sub_pc = (size_t)I->x;
                int width = (int)I->y; // Width in characters
                size_t probe_start_idx = t.idx;

                if (t.idx == 0) {
                    free_thread(&t);
                    break;
                }                

                // Move backward by 'width' characters in UTF-8 string
                size_t chars_to_move = width;
                size_t byte_idx = t.idx;
                while (chars_to_move > 0 && byte_idx > 0) {
                    byte_idx--;
                    // Check if we're at the start of a UTF-8 character
                    while (byte_idx > 0 && (s[byte_idx] & 0xC0) == 0x80) {
                        byte_idx--; // Skip continuation bytes
                    }
                    chars_to_move--;
                }
                if (chars_to_move > 0) {
                    // Not enough characters to move back
                    free_thread(&t);
                    break;
                }
                probe_start_idx = byte_idx;

                Threads probe_q = {0};
                Thread probe_initial = clone_thread(&t, sub_pc, probe_start_idx);
                if (!probe_initial.caps) {
                    // Probe initialization failed
                    free_thread(&t);
                    break;
                }
                push(&probe_q, probe_initial, v);

                int probe_res = run_vm_engine(code, pcs, s, n, capture, NULL, NULL, &probe_q, v, true);

                while (probe_q.len > 0) {
                    Thread to_free = pop(&probe_q);
                    free_thread(&to_free);
                }
                free(probe_q.data);

                bool assert_holds = (probe_res == 1) != is_neg;
                if (assert_holds) {
                    Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                    if (nt.caps) push(q, nt, v);
                }
                free_thread(&t);
                break;
            }
            case I_MATCH: // Handled at top
            case I_ASUCCESS:
                // These are handled at the top of the loop. If reached here, it's an
                // anomaly (e.g., I_MATCH in a probe). Treat as no-op.
                free_thread(&t);
                break;
                
            case I_SPLIT: {
                Thread t1 = clone_thread(&t, (size_t)I->x, t.idx);
                Thread t2 = clone_thread(&t, (size_t)I->y, t.idx); // Create alternative threads
                if (t2.caps) push(q, t2, v);
                if (t1.caps) push(q, t1, v);
                free_thread(&t);
                break;
            }
            case I_JMP: {
                Thread nt = clone_thread(&t, (size_t)I->x, t.idx);
                if (nt.caps) push(q, nt, v);
                free_thread(&t);
                break;
            }
            case I_SAVE: {
                Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                if (nt.caps) {
                    if (I->val < nt.cap_size) {
                        nt.caps[I->val] = t.idx;
                    }
                    push(q, nt, v);
                }
                free_thread(&t);
                // Save capture position
                break;
            }
            case I_CHAR: {
                uintptr_t raw   = I->val;
                bool  caseless  = (raw & CASELESS_BIT) != 0;
                uint32_t pat_cp = (uint32_t)(raw & ~CASELESS_BIT);

                if (t.idx < n) {
                    size_t new_idx = t.idx;  uint32_t cp;
                    if (utf8_codepoint(s, n, &new_idx, &cp)) {
                        bool ok;
                        if (caseless && cp < 128) {
                            ok = tolower((int)cp) == (int)pat_cp;
                        } else {
                            ok = cp == pat_cp;
                        }
                        if (ok) {
                            Thread nt = clone_thread(&t, t.pc + 1, new_idx);
                            if (nt.caps) push(q, nt, v);
                        }
                    }
                }
                free_thread(&t);
                break;
            }
            case I_ANY: {
                if (t.idx < n) {
                    uint32_t cp; size_t new_idx = t.idx;
                    if (utf8_codepoint(s, n, &new_idx, &cp)) {
                        bool ign = I->val;
                        if (ign || (cp != '\r' && cp != '\n')) { // Match any char, optionally ignoring newlines
                            Thread nt = clone_thread(&t, t.pc + 1, new_idx);
                            if (nt.caps) push(q, nt, v);
                        }
                    }
                }
                free_thread(&t);
                break;
            }
            case I_UNIPROP:
            case I_UNIPROP + 128: {
                if (t.idx < n) {
                    uint32_t cp; size_t new_idx = t.idx;
                    if (utf8_codepoint(s, n, &new_idx, &cp)) {
                        uint32_t *bitmap = (uint32_t*)I->val;
                        bool is_neg = (I->op & 128);
                        // Check if codepoint is in the property bitmap
                        bool in_set = (cp < 0x110000) && (bitmap[cp >> 5] & (1u << (cp & 31)));
                        if (in_set != is_neg) {
                            Thread nt = clone_thread(&t, t.pc + 1, new_idx);
                            if (nt.caps) push(q, nt, v);
                        }
                    }
                }
                free_thread(&t);
                break;
            }            
            case I_BACKREF: {
                // Extract group # and caseless‐flag
                size_t group_idx = I->val;
                bool caseless   = (bool)I->x;
                size_t start_idx = group_idx * 2;
                size_t end_idx = group_idx * 2 + 1;
                
                if (start_idx >= t.cap_size || end_idx >= t.cap_size ||
                    t.caps[start_idx] == SIZE_MAX || t.caps[end_idx] == SIZE_MAX) {
                    free_thread(&t);
                    break;
                    // Group not captured, fail backref
                }
                
                size_t group_start = t.caps[start_idx];
                size_t group_end = t.caps[end_idx];
                size_t group_len = group_end - group_start;

                if (t.idx + group_len <= n) {
                    if (!caseless) {
                        // case-sensitive fast path
                        if (memcmp(s + group_start, s + t.idx, group_len) == 0) {
                            Thread nt = clone_thread(&t, t.pc + 1, t.idx + group_len);
                            if (nt.caps) push(q, nt, v);
                        }
                    }
                    else {
                        // case-insensitive: decode utf8 & fold ASCII
                        size_t i1 = group_start, i2 = t.idx;
                        bool   ok = true;
                        while (i1 < group_end) {
                            uint32_t cp1, cp2;
                            size_t j1 = i1, j2 = i2;
                            if (!utf8_codepoint(s, group_end, &j1, &cp1) ||
                                !utf8_codepoint(s, n,         &j2, &cp2)) {
                                ok = false;
                                break;
                            }
                            if (cp1 < 128 && cp2 < 128) {
                                if (tolower((unsigned)cp1) != tolower((unsigned)cp2)) {
                                    ok = false;
                                    break;
                                }
                            }
                            else if (cp1 != cp2) {
                                ok = false;
                                break;
                            }
                            i1 = j1;
                            i2 = j2;
                        }
                        if (ok) {
                            Thread nt = clone_thread(&t, t.pc + 1, i2);
                            if (nt.caps) push(q, nt, v);
                        }
                    }
                }
                free_thread(&t);
                break;
            }
            case I_BOL:
            case I_MBOL: {
                bool ml = (I->op == I_MBOL);
                bool bol, eol;
                advance_linenl(s, n, t.idx, ml, &bol, &eol);
                if (bol) {
                    Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                    if (nt.caps) push(q, nt, v);
                }
                free_thread(&t);
                break;
            }
            case I_EOL:
            case I_MEOL: {
                bool ml = (I->op == I_MEOL);
                bool bol, eol;
                advance_linenl(s, n, t.idx, ml, &bol, &eol);
                if (eol) {
                    Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                    if (nt.caps) push(q, nt, v);
                }
                free_thread(&t);
                break;
            }
            case I_BOUND: { // Word boundary assertion
                bool is_word = (t.idx < n && (isalnum(s[t.idx]) || s[t.idx] == '_'));
                bool was_word = (t.idx > 0 && (isalnum(s[t.idx - 1]) || s[t.idx - 1] == '_'));
                if (is_word != was_word) {
                    Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                    if (nt.caps) push(q, nt, v);
                }
                free_thread(&t);
                break;
            }
            case I_NBOUND: {
                bool is_word  = (t.idx < n && (isalnum(s[t.idx]) || s[t.idx] == '_'));
                bool was_word = (t.idx > 0 && (isalnum(s[t.idx-1]) || s[t.idx-1] == '_'));
                if (is_word == was_word) {
                    Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                    if (nt.caps) push(q, nt, v);
                }
                free_thread(&t);
                break;
            }
            case I_SBOL: {
                if (t.idx == 0) {
                Thread nt = clone_thread(&t, t.pc + 1, t.idx);
                    if (nt.caps) push(q, nt, v);
                }
                free_thread(&t);
                break;
            }
            default:
                free_thread(&t);
                break;
        }
    }
    return 0; // No match found
    // All threads exhausted without success
}

/* -------------- finally the public function ------------------- */
int compile_regex_to_bytecode(regex_compiled* rx, regex_err* error) {
    CodeBuf buf = {0};
    buf.alloc = &rx->allocator;
    buf.arena = rx->arena;
    init_codebuf_subroutines(&buf, rx->capture_count);

    // Check for initialization failure
    if (buf.oom) {
        cleanup_codebuf_subroutines(&buf);
        error->code = REGEX_ERR_MEMORY;
        error->msg = regex_error_message(REGEX_ERR_MEMORY);
        return REGEX_ERR_MEMORY;
    }

    emit(&buf, (Instr){.op = I_SAVE, .val = 0});
    compile_node(&buf, rx->ast,
                 !!(rx->flags & REG_IGNORECASE),
                 !!(rx->flags & REG_SINGLELINE),
                 !!(rx->flags & REG_MULTILINE));
    emit(&buf, (Instr){.op = I_SAVE, .val = 1});
    emit(&buf, (Instr){.op = I_MATCH});

    if (buf.oom) {
        cleanup_codebuf_subroutines(&buf);
        if (buf.code) rx->allocator.free_func(buf.code, rx->allocator.user_data);
        error->code = REGEX_ERR_MEMORY;
        error->msg = regex_error_message(REGEX_ERR_MEMORY);
        return REGEX_ERR_MEMORY;
    }

    // Transfer ownership of bytecode to the regex_compiled struct
    rx->code = buf.code;
    rx->pc = buf.pc;

    // Prevent cleanup from freeing the transferred code
    buf.code = NULL;
    cleanup_codebuf_subroutines(&buf);

    return REGEX_OK;
}

int
regex_match(regex_compiled *rx,
            const char *subject,
            size_t subject_len,
            regex_match_result *result)
{
    if (!rx || !subject || !result || !rx->code) return 0;

    int capture = rx->capture_count;
    // Temporary arrays for capture positions
    int *temp_starts = rx->allocator.malloc_func((capture + 1) * sizeof(int), rx->allocator.user_data);
    int *temp_ends = rx->allocator.malloc_func((capture + 1) * sizeof(int), rx->allocator.user_data);
    if (!temp_starts || !temp_ends) {
        if (temp_starts) rx->allocator.free_func(temp_starts, rx->allocator.user_data);
        if (temp_ends) rx->allocator.free_func(temp_ends, rx->allocator.user_data);
        return REGEX_ERR_MEMORY;
    }

    int match_result = 0;
    for (size_t offset = 0; offset <= subject_len && match_result <= 0; ++offset) {
        // Reset temps
        for (int i = 0; i <= capture; i++) {
            temp_starts[i] = -1;
            temp_ends[i] = -1;
        }
        match_result = run_vm(rx->code, rx->pc, (const uint8_t*)subject, subject_len, capture, temp_starts, temp_ends, offset);
        
        // Check for errors from run_vm
        if (match_result < 0) {
            rx->allocator.free_func(temp_starts, rx->allocator.user_data);
            rx->allocator.free_func(temp_ends, rx->allocator.user_data);
            return -match_result;  // Convert back to positive error code
        }
    }

    if (match_result == 1) {  // Match found
        result->match_start = temp_starts[0];
        result->match_end = temp_ends[0];

        // Count actual defined captures
        int actual_capture_count = 0;
        for (int i = 1; i <= capture; i++) {
            if (temp_starts[i] != -1 && temp_ends[i] != -1) {
                actual_capture_count = i;
            }
        }

        // Allocate result capture arrays
        result->capture_starts = rx->allocator.malloc_func(actual_capture_count * sizeof(int), rx->allocator.user_data);
        result->capture_ends = rx->allocator.malloc_func(actual_capture_count * sizeof(int), rx->allocator.user_data);
        if (!result->capture_starts || !result->capture_ends) {
            if (result->capture_starts) rx->allocator.free_func(result->capture_starts, rx->allocator.user_data);
            if (result->capture_ends) rx->allocator.free_func(result->capture_ends, rx->allocator.user_data);
            rx->allocator.free_func(temp_starts, rx->allocator.user_data);
            rx->allocator.free_func(temp_ends, rx->allocator.user_data);
            return REGEX_ERR_MEMORY;
        }

        for (int i = 0; i < actual_capture_count; ++i) {
            result->capture_starts[i] = temp_starts[i + 1];
            result->capture_ends[i] = temp_ends[i + 1]; // Copy captures (groups 1+)
        }
        result->capture_count = actual_capture_count;

        rx->allocator.free_func(temp_starts, rx->allocator.user_data);
        rx->allocator.free_func(temp_ends, rx->allocator.user_data);
    } else {
        rx->allocator.free_func(temp_starts, rx->allocator.user_data);
        rx->allocator.free_func(temp_ends, rx->allocator.user_data);
    }

    return match_result;  // 1 for match, 0 for no match
}
