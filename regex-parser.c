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
  * Implements a non-recursive, stack-based backtracking NFA algorithm.
    Alternative execution paths (NFA states) are managed on an explicit stack.
  * Uses a "visited" set for memoization to prevent redundant work and handle
    complex patterns with overlapping subproblems efficiently.
- Pluggable Memory Management:
  * Core API supports custom allocators ('malloc', 'realloc', 'free'),
    allowing integration into projects with specific memory strategies.
  * The parser uses an internal arena allocator for efficient AST node
    management during compilation.
- Comprehensive PCRE2 Compatibility:
  * Supports a wide array of advanced constructs found in PCRE2 and Perl.
  * The implementation is validated by a test suite covering syntax, matching,
    edge cases, and error conditions.
- Detailed Error Reporting:
  * Provides structured error objects with error codes, messages, and the
    exact line/column number of the error in the pattern.
- Unicode-Awareness:
  * Full UTF-8 support in both the parser and the matching engine.
  * Built-in support for Unicode property matching (\p, \P) using a
    partial, internal Unicode character database to generate efficient bitmaps.

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
  * Capturing groups are compiled into self-contained, callable subroutines
    invoked via dedicated I_CALL and I_RETURN instructions.
- NFA Virtual Machine (VM):
  * The core matching logic is a loop processing VM instructions.
  * Backtracking is managed by pushing alternative execution paths (threads)
    onto a stack.
  * Instructions for advanced features like atomic groups ('I_MARK_ATOMIC',
    'I_CUT_TO_MARK'), conditionals ('I_GCOND'), and assertions ('I_ACOND', 'I_LBCOND').
- Unicode:
  * Safe, single-pass UTF-8 decoding.
  * Unicode property matching uses a built-in table of character ranges
    to build bitmaps. These bitmaps are allocated in the AST's memory arena
    for efficient cleanup.
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
- Partial POSIX support (common classes like [[:alpha:]], Unicode-aware where database allows).

Current Limitations:
--------------------
- No AST or bytecode optimization passes are currently performed.
- Lookbehind assertions must be fixed-length (variable-length lookbehind is not supported).
- Maximum lookbehind length is 255 characters (PCRE2 compatible).
- The built-in Unicode property support is based on a partial character database and does not cover all scripts or categories.
- Recursion/subroutine depth limited to 32 (MAX_CALL_DEPTH).
- POSIX classes partially supported and Unicode-aware only for covered properties.
- No full grapheme matching or script runs.
- No support for '\g{...}' backreference/subroutine syntax (use '\k<>', '(?n)' instead).
- No support for script runs or grapheme clusters ('\X').
- No support for generic newline sequences ('\R').
- No support for control verbs like '(*SKIP)', '(*FAIL)', '(*ACCEPT)'.
- No support for callouts.

===============================================================================
*/

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include "regex-parser.h"
#include "regex-unicode.h"
#include "regex-internals.h"

// ----------------------------------------------------------------------------
// 1. Allocator Implementation
// ----------------------------------------------------------------------------

// Default allocator implementation using standard library functions
static void* default_malloc(size_t size, void* user_data) {
    (void)user_data; // Unused
    return malloc(size);
}

static void default_free(void* ptr, void* user_data) {
    (void)user_data; // Unused
    free(ptr);
}

static void* default_realloc(void* ptr, size_t new_size, void* user_data) {
    (void)user_data; // Unused
    return realloc(ptr, new_size);
}

// Global static instance of the default allocator for convenience.
static const regex_allocator default_allocator = {
    .malloc_func = default_malloc,
    .free_func = default_free,
    .realloc_func = default_realloc,
    .user_data = NULL
};

// ----------------------------------------------------------------------------
// 2. Arena Allocation
// ----------------------------------------------------------------------------

void *arena_alloc(AstArena *arena, size_t size) {
    if (!arena->blocks || arena->blocks->used + size > arena->blocks->cap) {
        size_t cap = size > 64*1024 ? size : 64*1024;
        Block *block = arena->allocator.malloc_func(sizeof(Block), arena->allocator.user_data);
        if (!block) return NULL;
        
        block->data = arena->allocator.malloc_func(cap, arena->allocator.user_data);
        if (!block->data) {
            arena->allocator.free_func(block, arena->allocator.user_data);
            return NULL;
        }
        
        block->used = 0;
        block->cap = cap;
        block->next = arena->blocks;
        arena->blocks = block;
        arena->total_allocated += cap;
    }
    
    void *ptr = (char*)arena->blocks->data + arena->blocks->used;
    arena->blocks->used += size;
    return ptr;
}

static void arena_free(AstArena *arena) {
    Block *block = arena->blocks;
    while (block) {
        Block *next = block->next;
        arena->allocator.free_func(block->data, arena->allocator.user_data);
        arena->allocator.free_func(block, arena->allocator.user_data);
        block = next;
    }
    arena->blocks = NULL;
    arena->total_allocated = 0;
}

// ----------------------------------------------------------------------------
// 3. Error Handling
// ----------------------------------------------------------------------------

static const char* error_messages[] = {
    [REGEX_OK] = "Success",
    [REGEX_ERR_MEMORY] = "Memory allocation failed",
    [REGEX_ERR_INVALID_SYNTAX] = "Invalid regex syntax",
    [REGEX_ERR_INVALID_UTF8] = "Invalid UTF-8 sequence",
    [REGEX_ERR_INVALID_ESCAPE] = "Invalid escape sequence",
    [REGEX_ERR_INVALID_CLASS] = "Invalid character class syntax",
    [REGEX_ERR_INVALID_QUANT] = "Invalid quantifier",
    [REGEX_ERR_INVALID_GROUP] = "Invalid group syntax",
    [REGEX_ERR_INVALID_BACKREF] = "Invalid backreference",
    [REGEX_ERR_INVALID_PROP] = "Unknown Unicode property",
    [REGEX_ERR_UNMATCHED_PAREN] = "Unmatched parenthesis",
    [REGEX_ERR_INVALID_RANGE] = "Invalid range in character class",
    [REGEX_ERR_LOOKBEHIND_VAR] = "Lookbehind assertion is not fixed-length",
    [REGEX_ERR_LOOKBEHIND_LONG] = "Lookbehind assertion is too long",
    [REGEX_ERR_DUPLICATE_NAME] = "Duplicate capture group name",
    [REGEX_ERR_UNDEFINED_GROUP] = "Reference to undefined group",
    [REGEX_ERR_INVALID_CONDITION] = "Invalid conditional pattern",
};

const char* regex_error_message(int error_code) {
    size_t num_errors = sizeof(error_messages) / sizeof(error_messages[0]);
    if (error_code < 0 || (size_t)error_code >= num_errors) {
        return "Unknown error";
    }
    return error_messages[error_code];
}

// ----------------------------------------------------------------------------
// 4. Updated Parser State and Error Handling
// ----------------------------------------------------------------------------

// Fixup structure for deferred validation
typedef struct {
    RegexNode *node;
    char *name;
} Fixup;

typedef struct {
    char* name;
    int index;
} NamedGroup;

// Parser state
typedef struct {
    const char *pattern;
    int pos;
    int capture_count;
    regex_err error;
    bool has_error;
    int line_number;
    int column_start;
    NamedGroup *named_groups;
    int named_group_count;
    int named_group_capacity;
    uint32_t flags;
    AstArena *arena;
    Fixup *fixups;
    int fixup_count;
    int fixup_capacity;
    unsigned compile_flags;
    bool in_conditional;
} ParserState;

// Wrapper for strdup using the provided allocator
static char* pstrdup(ParserState* state, const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* new_str = state->arena->allocator.malloc_func(len, state->arena->allocator.user_data);
    if (!new_str) return NULL;
    memcpy(new_str, s, len);
    return new_str;
}

// Updated set_error to populate the structured error object
void set_error(ParserState *state, int error_code, const char *msg_override) {
    if (state->has_error) return;

    int line = 1;
    int col = 1;
    for (int i = 0; i < state->pos; i++) {
        if (state->pattern[i] == '\n') {
            line++;
            col = 1;
        } else {
            col++;
        }
    }

    state->error.code = error_code;
    state->error.pos = state->pos;
    state->error.line = line;
    state->error.col = col;
    state->error.msg = msg_override ? msg_override : regex_error_message(error_code);
    state->has_error = true;
}

// ----------------------------------------------------------------------------
// 5. UTF-8 Decoder and Unicode Support
// ----------------------------------------------------------------------------

static size_t utf8_decode(const char *str, uint32_t *codepoint) {
    const unsigned char *s = (const unsigned char*)str;
    
    if (s[0] < 0x80) {
        *codepoint = s[0];
        return 1;
    } else if ((s[0] & 0xE0) == 0xC0) {
        if ((s[1] & 0xC0) != 0x80) return 0;
        *codepoint = ((s[0] & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    } else if ((s[0] & 0xF0) == 0xE0) {
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        *codepoint = ((s[0] & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return 3;
    } else if ((s[0] & 0xF8) == 0xF0) {
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
        *codepoint = ((s[0] & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return 4;
    }
    return 0;
}

static char *ascii_lower(const char *str, ParserState* state) {
    size_t len = strlen(str);
    char *result = state->arena->allocator.malloc_func(len + 1, state->arena->allocator.user_data);
    if (!result) {
        set_error(state, REGEX_ERR_MEMORY, NULL);
        return NULL;
    }
    
    for (size_t i = 0; i < len; i++) {
        result[i] = (char) tolower(str[i]);
    }
    result[len] = '\0';
    return result;
}

// ----------------------------------------------------------------------------
// 6. Unicode Properties Support
// ----------------------------------------------------------------------------

// Enhanced property existence check
static bool unicode_property_exists(const char* name) {
    if (!name) return false;
    
    // Check standard Unicode categories
    const char* standard_props[] = {
        "l", "lu", "ll", "lt", "lm", "lo",     // Letters
        "m", "mn", "mc", "me",                 // Marks
        "n", "nd", "nl", "no",                 // Numbers
        "p", "pc", "pd", "ps", "pe", "pi", "pf", "po", // Punctuation
        "s", "sm", "sc", "sk", "so",           // Symbols
        "z", "zs", "zl", "zp",                 // Separators
        "c", "cc", "cf", "cs", "co", "cn",     // Other
        NULL
    };
    
    for (int i = 0; standard_props[i]; i++) {
        if (strcmp(name, standard_props[i]) == 0) {
            return true;
        }
    }
    
    // Check common aliases
    const char* aliases[] = {
        "alpha", "alnum", "digit", "space", "upper", "lower", "punct", "word",
        NULL
    };
    
    for (int i = 0; aliases[i]; i++) {
        if (strcmp(name, aliases[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

// ----------------------------------------------------------------------------
// 7. Forward declarations
// ----------------------------------------------------------------------------
RegexNode* parse_regex(ParserState *state);
RegexNode* parse_term(ParserState *state);
RegexNode* parse_factor(ParserState *state);
RegexNode* parse_atom(ParserState *state);
void set_error(ParserState *state, int error_code, const char *msg_override);
int compute_width(RegexNode *node, int *min, int *max);

// ----------------------------------------------------------------------------
// 8. Helper functions for creating AST nodes
// ----------------------------------------------------------------------------
RegexNode* create_node(RegexNodeType type, ParserState *state) {
    RegexNode *node = (RegexNode*)arena_alloc(state->arena, sizeof(RegexNode));
    if (!node) {
        set_error(state, REGEX_ERR_MEMORY, NULL);
        return NULL;
    }
    memset(node, 0, sizeof(RegexNode));
    node->type = type;
    node->token_start = state ? state->column_start : -1;
    node->token_end = state ? state->pos : -1;
    return node;
}

RegexNode* create_char_node(uint32_t codepoint, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_CHAR, state);
    if (!node) return NULL;
    node->data.codepoint = codepoint;
    return node;
}

RegexNode* create_concat_node(RegexNode *left, RegexNode *right, ParserState *state) {
    if (!left && !right) {
        RegexNode *node = create_node(REGEX_NODE_CONCAT, state);
        if (!node) return NULL;
        node->data.children.left = NULL;
        node->data.children.right = NULL;
        return node;
    }
    if (!left) return right;
    if (!right) return left;
    
    RegexNode *node = create_node(REGEX_NODE_CONCAT, state);
    if (!node) return NULL;
    node->data.children.left = left;
    node->data.children.right = right;
    return node;
}

RegexNode* create_alternation_node(RegexNode *left, RegexNode *right, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_ALTERNATION, state);
    if (!node) return NULL;
    node->data.children.left = left;
    node->data.children.right = right;
    return node;
}

RegexNode* create_quantifier_node(RegexNode *child, int min, int max, QuantifierType type, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_QUANTIFIER, state);
    if (!node) return NULL;
    node->data.quantifier.child = child;
    node->data.quantifier.min = min;
    node->data.quantifier.max = max;
    node->data.quantifier.quant_type = type;
    return node;
}

RegexNode* create_group_node(RegexNode *child, int capture_index, char *name, bool is_atomic, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_GROUP, state);
    if (!node) return NULL;
    node->data.group.child = child;
    node->data.group.capture_index = capture_index;
    node->data.group.name = name;
    node->data.group.is_atomic = is_atomic;
    node->data.group.enter_flags = 0;
    node->data.group.exit_flags = 0;
    return node;
}

RegexNode* create_char_class_node(char *set, bool negated, bool is_posix, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_CHAR_CLASS, state);
    if (!node) return NULL;
    node->data.char_class.set = set;
    node->data.char_class.negated = negated;
    node->data.char_class.is_posix = is_posix;
    return node;
}

RegexNode* create_anchor_node(char type, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_ANCHOR, state);
    if (!node) return NULL;
    node->data.anchor_type = type;
    return node;
}

RegexNode* create_dot_node(ParserState *state) {
    return create_node(REGEX_NODE_DOT, state);
}

RegexNode* create_backref_node(int index, char *name, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_BACKREF, state);
    if (!node) return NULL;
    node->data.backref.ref_index = index;
    node->data.backref.ref_name = name;
    return node;
}

RegexNode* create_assertion_node(RegexNode *child, AssertionType type, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_ASSERTION, state);
    if (!node) return NULL;
    node->data.assertion.child = child;
    node->data.assertion.assert_type = type;
    return node;
}

RegexNode* create_uni_prop_node(bool negated, char *prop_name, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_UNI_PROP, state);
    if (!node) return NULL;
    node->data.uni_prop.negated = negated;
    node->data.uni_prop.prop_name = prop_name;
    return node;
}

RegexNode* create_conditional_node(Condition cond, RegexNode *if_true, RegexNode *if_false, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_CONDITIONAL, state);
    if (!node) return NULL;
    node->data.conditional.cond = cond;
    node->data.conditional.if_true = if_true;
    node->data.conditional.if_false = if_false;
    return node;
}

RegexNode* create_subroutine_node(bool is_recursion, int target_index, char *target_name, ParserState *state) {
    RegexNode *node = create_node(REGEX_NODE_SUBROUTINE, state);
    if (!node) return NULL;
    node->data.subroutine.is_recursion = is_recursion;
    node->data.subroutine.target_index = target_index;
    node->data.subroutine.target_name = target_name;
    return node;
}

// ----------------------------------------------------------------------------
// 9. Fixup and Named Group Management
// ----------------------------------------------------------------------------

static void add_fixup(ParserState *state, RegexNode *node, char *name) {
    if (state->fixup_count >= state->fixup_capacity) {
        state->fixup_capacity = state->fixup_capacity > 0 ? state->fixup_capacity * 2 : 8;
        Fixup *new_fixups = state->arena->allocator.realloc_func(
            state->fixups, state->fixup_capacity * sizeof(Fixup), state->arena->allocator.user_data);
        if (!new_fixups) {
            set_error(state, REGEX_ERR_MEMORY, NULL);
            return;
        }
        state->fixups = new_fixups;
    }
    
    state->fixups[state->fixup_count].node = node;
    state->fixups[state->fixup_count].name = pstrdup(state, name);
    state->fixup_count++;
}

static int find_named_group_index(ParserState *state, const char *name) {
    for (int i = 0; i < state->named_group_count; i++) {
        if (strcmp(state->named_groups[i].name, name) == 0) {
            return state->named_groups[i].index;
        }
    }
    return -1;
}

static void process_fixups(ParserState *state) {
    for (int i = 0; i < state->fixup_count; i++) {
        Fixup *fixup = &state->fixups[i];
        int group_index = find_named_group_index(state, fixup->name);
        
        if (group_index != -1) {
            if (fixup->node->type == REGEX_NODE_BACKREF) {
                fixup->node->data.backref.ref_index = group_index;
            } else if (fixup->node->type == REGEX_NODE_SUBROUTINE) {
                fixup->node->data.subroutine.target_index = group_index;
            }
        } else {
             if (fixup->node->type == REGEX_NODE_BACKREF) {
                set_error(state, REGEX_ERR_UNDEFINED_GROUP, "Backreference to undefined named group");
             } else {
                set_error(state, REGEX_ERR_UNDEFINED_GROUP, "Subroutine call to undefined named group");
             }
             return;
        }
    }
}

// ----------------------------------------------------------------------------
// 10. Named group management
// ----------------------------------------------------------------------------

static bool add_named_group(ParserState *state, const char *name, int capture_index) {
    for (int i = 0; i < state->named_group_count; i++) {
        if (strcmp(state->named_groups[i].name, name) == 0) {
            set_error(state, REGEX_ERR_DUPLICATE_NAME, NULL);
            return false;
        }
    }

    if (state->named_group_count >= state->named_group_capacity) {
        state->named_group_capacity = state->named_group_capacity > 0 ? state->named_group_capacity * 2 : 8;
        NamedGroup *new_groups = state->arena->allocator.realloc_func(
            state->named_groups, state->named_group_capacity * sizeof(NamedGroup), state->arena->allocator.user_data);
        if (!new_groups) {
            set_error(state, REGEX_ERR_MEMORY, NULL);
            return false;
        }
        state->named_groups = new_groups;
    }
    
    state->named_groups[state->named_group_count].name = pstrdup(state, name);
    if (!state->named_groups[state->named_group_count].name) {
        set_error(state, REGEX_ERR_MEMORY, NULL);
        return false;
    }
    state->named_groups[state->named_group_count].index = capture_index;
    state->named_group_count++;
    return true;
}

// ----------------------------------------------------------------------------
// 11. Parser utilities
// ----------------------------------------------------------------------------

static uint32_t peek_codepoint(ParserState *state) {
    if (state->pattern[state->pos] == '\0') return 0;
    uint32_t codepoint;
    size_t len = utf8_decode(&state->pattern[state->pos], &codepoint);
    if (len == 0) {
        set_error(state, REGEX_ERR_INVALID_UTF8, NULL);
        return 0;
    }
    return codepoint;
}

static uint32_t next_codepoint(ParserState *state) {
    state->column_start = state->pos;
    if (state->pattern[state->pos] == '\0') return 0;
    
    uint32_t codepoint;
    size_t len = utf8_decode(&state->pattern[state->pos], &codepoint);
    if (len == 0) {
        set_error(state, REGEX_ERR_INVALID_UTF8, NULL);
        return 0;
    }
    
    state->pos += (int) len;
    return codepoint;
}

static bool match_codepoint(ParserState *state, uint32_t expected) {
    if (peek_codepoint(state) == expected) {
        next_codepoint(state);
        return true;
    }
    return false;
}

static bool match_sequence(ParserState *state, const char *seq) {
    if (strncmp(&state->pattern[state->pos], seq, strlen(seq)) == 0) {
        state->pos += (int) strlen(seq);
        return true;
    }
    return false;
}

static bool parse_number(ParserState *state, int *out_value, int max_digits) {
    int start_pos = state->pos;
    char *end;
    long val = strtol(&state->pattern[state->pos], &end, 10);
    if (end == &state->pattern[state->pos] || (max_digits > 0 && (end - &state->pattern[start_pos] > max_digits))) {
        return false;
    }
    *out_value = (int)val;
    state->pos = (int)(end - state->pattern);
    return true;
}

static char* parse_plain_name(ParserState *state) {
    int start = state->pos;
    while (true) {
        uint32_t cp = peek_codepoint(state);
        if ((cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9') || cp == '_') {
            next_codepoint(state);
        } else {
            break;
        }
    }
    int end = state->pos;
    if (end == start) {
        set_error(state, REGEX_ERR_INVALID_CONDITION, "Missing name in subroutine call");
        return NULL;
    }
    int len = end - start;
    char *name = malloc(len + 1);
    if (!name) {
        set_error(state, REGEX_ERR_MEMORY, NULL);
        return NULL;
    }
    memcpy(name, &state->pattern[start], len);
    name[len] = '\0';
    return name;
}

static int hexval(uint32_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool is_quantifier(uint32_t cp) {
    return cp == '*' || cp == '+' || cp == '?' || cp == '{';
}

// ----------------------------------------------------------------------------
// 12. Width analysis for lookbehind validation
// ----------------------------------------------------------------------------

int compute_width(RegexNode *node, int *min, int *max) {
    if (!node) {
        *min = *max = 0;
        return 0;
    }
    
    switch (node->type) {
        case REGEX_NODE_CHAR:
        case REGEX_NODE_DOT:
        case REGEX_NODE_CHAR_CLASS:
        case REGEX_NODE_UNI_PROP:
            *min = *max = 1;
            return 0;
            
        case REGEX_NODE_ANCHOR:
        case REGEX_NODE_BACKREF: // Can have variable width
        case REGEX_NODE_SUBROUTINE:
             *min = 0; *max = -1; // Unbounded
             return 0;

        case REGEX_NODE_CONCAT: {
            int lmin, lmax, rmin, rmax;
            compute_width(node->data.children.left, &lmin, &lmax);
            compute_width(node->data.children.right, &rmin, &rmax);
            *min = lmin + rmin;
            *max = (lmax == -1 || rmax == -1) ? -1 : lmax + rmax;
            return 0;
        }
        
        case REGEX_NODE_ALTERNATION: {
            int lmin, lmax, rmin, rmax;
            compute_width(node->data.children.left, &lmin, &lmax);
            compute_width(node->data.children.right, &rmin, &rmax);
            *min = (lmin < rmin) ? lmin : rmin;
            *max = (lmax == -1 || rmax == -1) ? -1 : ((lmax > rmax) ? lmax : rmax);
            return 0;
        }
        
        case REGEX_NODE_QUANTIFIER: {
            int cmin, cmax;
            compute_width(node->data.quantifier.child, &cmin, &cmax);
            *min = cmin * node->data.quantifier.min;
            *max = (node->data.quantifier.max == -1 || cmax == -1) ? -1 : cmax * node->data.quantifier.max;
            return 0;
        }
        
        case REGEX_NODE_GROUP:
        case REGEX_NODE_BRESET_GROUP:
            return compute_width(node->data.group.child, min, max);

        case REGEX_NODE_CONDITIONAL: {
             int t_min, t_max, f_min = 0, f_max = 0;
             compute_width(node->data.conditional.if_true, &t_min, &t_max);
             if (node->data.conditional.if_false) {
                 compute_width(node->data.conditional.if_false, &f_min, &f_max);
             }
             *min = (t_min < f_min) ? t_min : f_min;
             *max = (t_max == -1 || f_max == -1) ? -1 : ((t_max > f_max) ? t_max : f_max);
             return 0;
        }

        default: // Assertions, comments are 0-width
            *min = *max = 0;
            return 0;
    }
}

static void check_lookbehind(RegexNode *node, ParserState *state) {
    int min, max;
    compute_width(node, &min, &max);
    /* PCRE2 allows different fixed‑length alternatives;   */
    /* it disallows only unbounded or too‑long paths.  */
    if (max == -1) {
        set_error(state, REGEX_ERR_LOOKBEHIND_VAR, 
            "Lookbehind assertion is not fixed length");
    }
    if (max > 255) { // same limit as PCRE
        set_error(state, REGEX_ERR_LOOKBEHIND_LONG, 
            "Lookbehind assertion is too long");
    }
}

// ----------------------------------------------------------------------------
// 13. Flag parsing for inline modifiers
// ----------------------------------------------------------------------------

static void scan_flag_string(const char *str, int *pos, uint32_t *flags) {
    bool negate = false;
    
    while (str[*pos] && str[*pos] != ')' && str[*pos] != ':') {
        char c = str[*pos];
        (*pos)++;
        
        if (c == '-') {
            negate = true;
            continue;
        }
        
        uint32_t flag = 0;
        switch (c) {
            case 'i': flag = REG_IGNORECASE; break;
            case 'm': flag = REG_MULTILINE; break;
            case 's': flag = REG_SINGLELINE; break;
            case 'x': flag = REG_EXTENDED; break;
            case 'U': flag = REG_UNGREEDY; break;
            default: continue;
        }
        
        if (negate) {
            *flags &= ~flag;
        } else {
            *flags |= flag;
        }
    }
}

// ----------------------------------------------------------------------------
// 14. Parsing functions
// ----------------------------------------------------------------------------

char* parse_char_class_content(ParserState *state, bool *is_posix) {
    *is_posix = false;
    int start_pos = state->pos;
    int nesting_level = 1;
    bool at_start = true;

    if (strncmp(&state->pattern[state->pos], "[[:", 3) == 0) {
        *is_posix = true;
    }

    while (state->pattern[state->pos] != '\0') {
        if (state->pattern[state->pos] == '\n') {
            set_error(state, REGEX_ERR_INVALID_SYNTAX, "Invalid newline in character class");
            return NULL;
        }

        if (state->pattern[state->pos] == '[' && !*is_posix) {
             if (strncmp(&state->pattern[state->pos], "[[:", 3) != 0) {
                 nesting_level++;
             }
        } else if (state->pattern[state->pos] == ']') {
            if (at_start) {
                // ']' is a literal if it's the first character
            } else {
                nesting_level--;
                if (nesting_level == 0) break;
            }
        } else if (state->pattern[state->pos] == '\\') {
            state->pos++;
            if (state->pattern[state->pos] != '\0') {
                state->pos++;
            }
            at_start = false;
            continue;
        }
        at_start = false;
        state->pos++;
    }

    if (nesting_level != 0) {
        set_error(state, REGEX_ERR_INVALID_SYNTAX, "Unmatched '[' in character class");
        return NULL;
    }

    int len = state->pos - start_pos;
    char *content = malloc(len + 1);
    if (!content) {
        set_error(state, REGEX_ERR_MEMORY, NULL);
        return NULL;
    }
    memcpy(content, &state->pattern[start_pos], len);
    content[len] = '\0';
    state->pos++; // consume closing ']'
    return content;
}

char* parse_group_name(ParserState *state) {
    uint32_t first = peek_codepoint(state);
    if (!(first >= 'A' && first <= 'Z') && !(first >= 'a' && first <= 'z') && first != '_') {
        set_error(state, REGEX_ERR_INVALID_SYNTAX, "Invalid group name: must start with letter or underscore");
        return NULL;
    }
    
    int start = state->pos;
    next_codepoint(state);
    
    while (true) {
        uint32_t cp = peek_codepoint(state);
        if ((cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9') || cp == '_') {
            next_codepoint(state);
        } else {
            break;
        }
    }
    
    if (!match_codepoint(state, '>')) {
        set_error(state, REGEX_ERR_UNMATCHED_PAREN, "Unmatched '<' in named group");
        return NULL;
    }
    
    int end = state->pos - 1; // back up over '>'
    int len = end - start;
    char *name = malloc(len + 1);
    if (!name) {
        set_error(state, REGEX_ERR_MEMORY, NULL);
        return NULL;
    }
    memcpy(name, &state->pattern[start], len);
    name[len] = '\0';
    return name;
}

static Condition parse_condition(ParserState *state) {
    Condition cond = {0};

    /* Look-ahead / look-behind assertions start with '?' here because
       the opening '(' has already been consumed. */
    if (peek_codepoint(state) == '?') {
        /* Rewind one byte to give parse_atom() the '(' it expects. */
        state->pos--;                 /* now on '('                 */
        cond.data.assertion = parse_atom(state);
        if (cond.data.assertion && cond.data.assertion->type == REGEX_NODE_ASSERTION) {
            cond.type = COND_ASSERTION;
            return cond;
        }
        set_error(state, REGEX_ERR_INVALID_CONDITION, "Condition is not a valid assertion");
        return cond;
    }

    // This handles '(?(?<=...) ...)'
    if (peek_codepoint(state) == '(') {
        cond.type = COND_ASSERTION;
        cond.data.assertion = parse_atom(state);
        if (state->has_error || !cond.data.assertion || cond.data.assertion->type != REGEX_NODE_ASSERTION) {
            set_error(state, REGEX_ERR_INVALID_CONDITION, "Condition is not a valid assertion");
            cond.type = COND_INVALID;
        }
    } else if (peek_codepoint(state) == '<' || peek_codepoint(state) == '\'') {
        cond.type = COND_NAMED;
        char opener = (char) next_codepoint(state);
        char closer = (opener == '<') ? '>' : '\'';
        
        int start = state->pos;
        while (peek_codepoint(state) != (uint32_t)closer && peek_codepoint(state) != 0) {
            next_codepoint(state);
        }
        if (!match_codepoint(state, closer)) {
            set_error(state, REGEX_ERR_UNMATCHED_PAREN, "Unclosed named condition");
            cond.type = COND_INVALID;
            return cond;
        }
        int len = state->pos - start - 1;
        cond.data.group_name = malloc(len + 1);
        if (!cond.data.group_name) {
            set_error(state, REGEX_ERR_MEMORY, NULL);
            cond.type = COND_INVALID;
            return cond;
        }
        memcpy(cond.data.group_name, &state->pattern[start], len);
        cond.data.group_name[len] = '\0';
        /* Make sure that name has already been declared. */
        if (cond.type == COND_NAMED) {
            if (find_named_group_index(state, cond.data.group_name) == -1) {
                set_error(state, REGEX_ERR_UNDEFINED_GROUP, "Conditional references undefined named group");
                cond.type = COND_INVALID;
            }
        }
    } else if (peek_codepoint(state) >= '0' && peek_codepoint(state) <= '9') {
        cond.type = COND_NUMERIC;
        if (!parse_number(state, &cond.data.group_index, 0)) {
            set_error(state, REGEX_ERR_INVALID_CONDITION, "Invalid group number in condition");
            cond.type = COND_INVALID;
        } else {
            /* The group must already exist (i.e. be to the left).            */
            if (cond.data.group_index <= 0 ||
                cond.data.group_index > state->capture_count) {
                set_error(state, REGEX_ERR_UNDEFINED_GROUP, "Conditional references undefined group");
                cond.type = COND_INVALID;
            }
        }
    } else {
        // This handles '(?(?=...) ...)'
        int old_pos = state->pos;
        state->pos--; // go back to the '('
        RegexNode* assertion = parse_atom(state);
        if(assertion && assertion->type == REGEX_NODE_ASSERTION) {
            cond.type = COND_ASSERTION;
            cond.data.assertion = assertion;
        } else {
            state->pos = old_pos;
            set_error(state, REGEX_ERR_INVALID_CONDITION, "Invalid condition");
        }
    }
    
    return cond;
}

RegexNode* parse_regex(ParserState *state) {
    RegexNode *node = parse_term(state);
    if (state->has_error) return NULL;

    while (!state->in_conditional && peek_codepoint(state) == '|') {
        next_codepoint(state);
        RegexNode *right = parse_term(state);
        if (state->has_error) return NULL;
        node = create_alternation_node(node, right, state);
        if (!node) return NULL;
    }
    return node;
}

RegexNode* parse_term(ParserState *state) {
    RegexNode *node = NULL;
    while (peek_codepoint(state) != 0 && peek_codepoint(state) != ')' && peek_codepoint(state) != '|') {
        RegexNode *factor = parse_factor(state);
        if (state->has_error) return NULL;
        if (factor) {
            node = create_concat_node(node, factor, state);
            if (!node) return NULL;
        }
    }
    return node ? node : create_concat_node(NULL, NULL, state);
}

RegexNode* parse_factor(ParserState *state) {
    RegexNode *atom = parse_atom(state);
    if (state->has_error || !atom) return atom;
    
    // Only anchors cannot be quantified in PCRE2  
    // Assertions can be quantified (though it's effectively a no-op for zero-width assertions)
    if (atom->type == REGEX_NODE_ANCHOR) {
        if (is_quantifier(peek_codepoint(state))) {
            set_error(state, REGEX_ERR_INVALID_QUANT, "Cannot quantify an anchor");
            return NULL;
        }
    }

    uint32_t q = peek_codepoint(state);
    int min = -1, max = -1;
    bool default_lazy = (state->flags & REG_UNGREEDY) != 0;
    QuantifierType quant_type = default_lazy ? QUANT_LAZY : QUANT_GREEDY;

    if (q == '*' || q == '+' || q == '?') {
        next_codepoint(state);
        min = (q == '+') ? 1 : 0;
        max = (q == '?') ? 1 : -1;
    } else if (q == '{') {
        next_codepoint(state);
        bool parsed_min = parse_number(state, &min, 0);
        if (!parsed_min) {
            min = 0;
        }
        if (match_codepoint(state, ',')) {
            if (peek_codepoint(state) == '}') {
                max = -1;
            } else if (!parse_number(state, &max, 0)) {
                set_error(state, REGEX_ERR_INVALID_QUANT, "Expected number after comma in quantifier {}");
                return NULL;
            }
        } else {
            if (!parsed_min) {
                set_error(state, REGEX_ERR_INVALID_QUANT, "Expected number in quantifier {}");
                return NULL;
            }
            max = min;
        }
        if (!match_codepoint(state, '}')) {
            set_error(state, REGEX_ERR_UNMATCHED_PAREN, "Unmatched '{' in quantifier");
            return NULL;
        }
    }

    if (min != -1) {
        if (min < 0 || (max != -1 && min > max)) {
            set_error(state, REGEX_ERR_INVALID_QUANT, "Invalid range in quantifier");
            return NULL;
        }
        
        if (match_codepoint(state, '?')) {
            /* '?' toggles greediness relative to the default */
            quant_type = default_lazy ? QUANT_GREEDY : QUANT_LAZY;
        } else if (match_codepoint(state, '+')) {
            quant_type = QUANT_POSSESSIVE;
        }

        if (is_quantifier(peek_codepoint(state))) {
            set_error(state, REGEX_ERR_INVALID_QUANT, "Double quantifier");
            return NULL;
        }
        
        return create_quantifier_node(atom, min, max, quant_type, state);
    }
    return atom;
}

RegexNode* parse_atom(ParserState *state) {
    uint32_t cp = peek_codepoint(state);
    if (cp == 0) return NULL;

    int atom_start_pos = state->pos;
    next_codepoint(state);

    switch (cp) {
        case '(': {
            // Check for extended syntaxes first
            if (peek_codepoint(state) == '?') {
                next_codepoint(state); // consume '?'

                if (match_sequence(state, "R)")) return create_subroutine_node(true, 0, NULL, state);
                
                if (match_codepoint(state, '|')) {
                    // Branch reset group.
                    // This logic is similar to parse_regex, but with capture count resets.
                    int save_count = state->capture_count;

                    // Parse the first branch.
                    RegexNode *alt = parse_term(state);
                    if (state->has_error) return NULL;

                    int max_captures_in_branch = state->capture_count;

                    while (peek_codepoint(state) == '|') {
                        next_codepoint(state);

                        // Reset capture count for the new branch.
                        state->capture_count = save_count;

                        RegexNode *more = parse_term(state);
                        if (state->has_error) return NULL;

                        // Update the maximum capture count seen across all branches.
                        if (state->capture_count > max_captures_in_branch) {
                            max_captures_in_branch = state->capture_count;
                        }

                        alt = create_alternation_node(alt, more, state);
                        if (!alt) return NULL;
                    }

                    // The total capture count for the pattern is the max of any branch.
                    state->capture_count = max_captures_in_branch;

                    if (!match_codepoint(state, ')')) {
                        set_error(state, REGEX_ERR_UNMATCHED_PAREN, "Unmatched '(' for branch reset group");
                        return NULL;
                    }

                    RegexNode *node = create_node(REGEX_NODE_BRESET_GROUP, state);
                    if (!node) return NULL;
                    node->data.group.child = alt;
                    return node;
                }
                
                if (match_codepoint(state, '(')) {
                    // Conditional pattern (?(...)...)
                    // We've just seen "(?(", now treat everything until the final ")" as
                    // inside the conditional context:
                    state->in_conditional = true;
                    Condition cond = parse_condition(state);
                    if (state->has_error || cond.type == COND_INVALID) {
                        state->in_conditional = false;   
                        return NULL;
                    }
                    
                    /* Only numeric and named conditions are followed by an
                    explicit ')' delimiter.  For assertion conditions the
                    ')' that closes the assertion already plays that role. */
                    if (cond.type != COND_ASSERTION) {
                        if (!match_codepoint(state, ')')) {
                            set_error(state, REGEX_ERR_UNMATCHED_PAREN, "Expected ')' after condition");
                            state->in_conditional = false;
                            return NULL;
                        }
                    }

                    RegexNode *yes = parse_regex(state);
                    if (state->has_error) {
                        state->in_conditional = false;
                        return NULL;
                    }
                    
                    RegexNode *no = NULL;
                    if (peek_codepoint(state) == '|') {
                        next_codepoint(state);
                        no = parse_regex(state);
                        if (state->has_error) {
                            state->in_conditional = false;
                            return NULL;
                        }
                    }
                    state->in_conditional = false;
                    
                    if (!match_codepoint(state, ')')) { set_error(state, REGEX_ERR_UNMATCHED_PAREN, "Unmatched '(' for conditional"); return NULL; }
                    
                    return create_conditional_node(cond, yes, no, state);
                }

                bool is_assertion = false, non_capturing = false, is_atomic = false;
                AssertionType assert_type = 0;
                char *name = NULL;
                uint32_t old_flags = state->flags;
                int capture_index = -1;

                uint32_t next_c = peek_codepoint(state);
                switch (next_c) {
                    case ':': next_codepoint(state); non_capturing = true; break;
                    case '=': next_codepoint(state); is_assertion = true; assert_type = ASSERT_LOOKAHEAD_POS; break;
                    case '!': next_codepoint(state); is_assertion = true; assert_type = ASSERT_LOOKAHEAD_NEG; break;
                    case '>': next_codepoint(state); is_atomic = true; break;
                    case '#':
                        next_codepoint(state);
                        while (peek_codepoint(state) != ')' && peek_codepoint(state) != 0) next_codepoint(state);
                        if (!match_codepoint(state, ')')) { set_error(state, REGEX_ERR_INVALID_SYNTAX, "Unclosed comment"); return NULL; }
                        return create_node(REGEX_NODE_COMMENT, state);
                    case '<': {
                        next_codepoint(state);
                        uint32_t next_next = peek_codepoint(state);
                        if (next_next == '=') { next_codepoint(state); is_assertion = true; assert_type = ASSERT_LOOKBEHIND_POS; } 
                        else if (next_next == '!') { next_codepoint(state); is_assertion = true; assert_type = ASSERT_LOOKBEHIND_NEG; } 
                        else {
                            name = parse_group_name(state);
                            if (!name) return NULL;
                            capture_index = ++state->capture_count;
                            if (!add_named_group(state, name, capture_index)) { free(name); return NULL; }
                        }
                        break;
                    }
                    case 'i': case 'm': case 's': case 'x': case 'U': case '-': {
                        int flag_pos = state->pos;
                        scan_flag_string(state->pattern, &flag_pos, &state->flags);
                        state->pos = flag_pos;
                        
                        if (match_codepoint(state, ':')) {
                            RegexNode *child = parse_regex(state);
                            if (state->has_error) { state->flags = old_flags; return NULL; }
                            if (!match_codepoint(state, ')')) { set_error(state, REGEX_ERR_UNMATCHED_PAREN, "Unmatched '(' for scoped flags"); state->flags = old_flags; return NULL; }
                            RegexNode *group = create_group_node(child, -1, NULL, false, state);
                            if (!group) { state->flags = old_flags; return NULL; }
                            group->data.group.enter_flags = old_flags;
                            group->data.group.exit_flags = state->flags;
                            state->flags = old_flags;
                            return group;
                        } else if (match_codepoint(state, ')')) {
                            RegexNode *g = create_group_node(NULL, -1, NULL, false, state);
                            if (g) {
                                g->data.group.enter_flags = old_flags;
                                g->data.group.exit_flags  = state->flags;
                            }
                            return g;
                        } else { set_error(state, REGEX_ERR_INVALID_SYNTAX, "Expected ':' or ')' after flags"); return NULL; }
                    }
                    default: {
                        int num_val = 0;
                        int old_pos = state->pos;
                        if (parse_number(state, &num_val, 0) && match_codepoint(state, ')')) {
                            return create_subroutine_node(false, num_val, NULL, state);
                        }
                        state->pos = old_pos;
                        
                        if (match_codepoint(state, '&')) {
                            char *target_name = parse_plain_name(state);
                            if (!target_name) return NULL;
                            if (!match_codepoint(state, ')')) { set_error(state, REGEX_ERR_INVALID_SYNTAX, "Unclosed subroutine call"); free(target_name); return NULL; }
                            RegexNode *node = create_subroutine_node(false, 0, target_name, state);
                            if (!node) { free(target_name); return NULL; }
                            add_fixup(state, node, target_name);
                            return node;
                        }

                        set_error(state, REGEX_ERR_INVALID_SYNTAX, "Invalid syntax after '(?'"); return NULL;
                    }
                }
                // Common logic for groups parsed above
                if (!is_assertion && !non_capturing && !is_atomic && !name) { // !name: skip increment for named groups since it was already done
                    capture_index = ++state->capture_count;
                }
                RegexNode *sub_expr = parse_regex(state);
                if (state->has_error) { free(name); return NULL; }
                if (!match_codepoint(state, ')')) { set_error(state, REGEX_ERR_UNMATCHED_PAREN, "Unmatched '('"); free(name); return NULL; }
                
                if (is_assertion) {
                    if (assert_type == ASSERT_LOOKBEHIND_POS || assert_type == ASSERT_LOOKBEHIND_NEG) {
                        check_lookbehind(sub_expr, state);
                        if (state->has_error) return NULL;
                    }
                    return create_assertion_node(sub_expr, assert_type, state);
                } else {
                    return create_group_node(sub_expr, capture_index, name, is_atomic, state);
                }
            }
            
            // Standard capturing group
            int capture_index = ++state->capture_count;
            RegexNode *sub_expr = parse_regex(state);
            if (state->has_error) return NULL;
            if (!match_codepoint(state, ')')) { set_error(state, REGEX_ERR_UNMATCHED_PAREN, "Unmatched '('"); return NULL; }
            return create_group_node(sub_expr, capture_index, NULL, false, state);
        }
        
        case '[': {
            bool negated = match_codepoint(state, '^');
            bool is_posix;
            char *set = parse_char_class_content(state, &is_posix);
            if (state->has_error || !set) { free(set); return NULL; }

            if (!is_posix && set[0] == '\0' && !negated) {
                 if (state->pattern[state->pos - 2] == ']') { // check for []
                    free(set);
                    set_error(state, REGEX_ERR_INVALID_CLASS, "Empty character class");
                    return NULL;
                }
            }
            for (int i = 0; set[i]; i++) {
                if (set[i] == '\\' && (set[i+1] == 'd' || set[i+1] == 'D' || set[i+1] == 'w' || set[i+1] == 'W' || set[i+1] == 's' || set[i+1] == 'S') && set[i+2] == '-') {
                    free(set);
                    set_error(state, REGEX_ERR_INVALID_RANGE, "Invalid range in character class");
                    return NULL;
                }
            }
            return create_char_class_node(set, negated, is_posix, state);
        }
        
        case '\\': {
            uint32_t escaped = next_codepoint(state);
            if (escaped == 0) { set_error(state, REGEX_ERR_INVALID_ESCAPE, "Incomplete escape"); return NULL; }

            if (escaped == 'p' || escaped == 'P') {
                bool neg = (escaped == 'P');
                if (!match_codepoint(state, '{')) { set_error(state, REGEX_ERR_INVALID_SYNTAX, "Expected '{' after \\p"); return NULL; }
                int start = state->pos;
                while (peek_codepoint(state) != '}' && peek_codepoint(state) != 0) next_codepoint(state);
                if (!match_codepoint(state, '}')) { set_error(state, REGEX_ERR_INVALID_SYNTAX, "Unclosed property escape"); return NULL; }

                int len = state->pos - start - 1;
                char *raw = malloc(len + 1);
                if (!raw) { set_error(state, REGEX_ERR_MEMORY, NULL); return NULL; }
                memcpy(raw, &state->pattern[start], len);
                raw[len] = '\0';
                
                char *name = ascii_lower(raw, state);
                free(raw);
                
                if (!unicode_property_exists(name)) { set_error(state, REGEX_ERR_INVALID_PROP, "Unknown Unicode property"); free(name); return NULL; }
                return create_uni_prop_node(neg, name, state);
            }
            
            if (escaped == 'x' || escaped == 'u') {
                uint32_t code = 0;
                int digits = 0;
                if (match_codepoint(state, '{')) {
                    while (digits < 8) {
                        uint32_t c = peek_codepoint(state);
                        int val = hexval(c);
                        if (val == -1) break;
                        code = (code << 4) | val;
                        next_codepoint(state);
                        digits++;
                    }
                    if (!match_codepoint(state, '}')) { set_error(state, REGEX_ERR_INVALID_SYNTAX, "Unclosed hex escape"); return NULL; }
                    return create_char_node(code, state);
                } else {
                    int num_digits = (escaped == 'x') ? 2 : 4;
                    for(int i = 0; i < num_digits; i++) {
                        uint32_t c = peek_codepoint(state);
                        int val = hexval(c);
                        if (val == -1) { set_error(state, REGEX_ERR_INVALID_ESCAPE, "Invalid hex escape sequence"); return NULL; }
                        code = (code << 4) | val;
                        next_codepoint(state);
                    }
                    return create_char_node(code, state);
                }
            }
            
            if (escaped == 'Q') {
                int start = state->pos;
                while (state->pattern[state->pos] && !(state->pattern[state->pos] == '\\' && state->pattern[state->pos+1] == 'E')) state->pos++;
                if (state->pattern[state->pos] == '\0') { set_error(state, REGEX_ERR_INVALID_ESCAPE, "Unclosed \\Q"); return NULL; }
                int end = state->pos;
                state->pos += 2;
                
                RegexNode *seq = NULL;
                for (int i = start; i < end; ) {
                    uint32_t codepoint;
                    size_t len = utf8_decode(&state->pattern[i], &codepoint);
                    if (len == 0) { set_error(state, REGEX_ERR_INVALID_UTF8, "Invalid UTF-8 in \\Q...\\E"); return NULL; }
                    i += (int) len;
                    RegexNode *char_node = create_char_node(codepoint, state);
                    if (!char_node) return NULL;
                    seq = create_concat_node(seq, char_node, state);
                    if (!seq) return NULL;
                }
                return seq;
            }

            if (escaped >= '0' && escaped <= '9') {
                state->pos = atom_start_pos + 1; // back up
                int ref_val = 0;
                parse_number(state, &ref_val, 0);
                // we defer validity checking until after we know the total group count
                return create_backref_node(ref_val, NULL, state);
            }
            
            if (escaped == 'k') {
                if (!match_codepoint(state, '<')) {
                    set_error(state, REGEX_ERR_INVALID_SYNTAX, "Expected '<' after \\k");
                    return NULL;
                }
                char *name = parse_group_name(state);
                if (!name) return NULL;
                int group_index = find_named_group_index(state, name);
                RegexNode *node = create_backref_node(group_index, name, state);
                if (!node) { free(name); return NULL; }
                if (group_index == -1) {
                    // Defer validation; add a fixup for later resolution.
                    add_fixup(state, node, name);
                }
                return node;
            }
            
            switch (escaped) {
                case 'd': case 'D': case 's': case 'S': case 'w': case 'W': {
                    char *set_str = malloc(3);
                    if (!set_str) { set_error(state, REGEX_ERR_MEMORY, NULL); return NULL; }
                    sprintf(set_str, "\\%c", (char)escaped);
                    return create_char_class_node(set_str, false, false, state);
                }
                case 'b': return create_anchor_node('b', state);
                case 'B': return create_anchor_node('B', state);
                case 'A': return create_anchor_node('A', state);
                case 'z': return create_anchor_node('z', state);
                case 't': return create_char_node('\t', state);
                case 'n': return create_char_node('\n', state);
                case 'r': return create_char_node('\r', state);
                case 'f': return create_char_node('\f', state);
                default: return create_char_node(escaped, state);
            }
        }
        
        case '.': return create_dot_node(state);
        
        case '^': return create_anchor_node('^', state);
        case '$': return create_anchor_node('$', state);
        
        case ')': case '|': case '*': case '+': case '?': case '{': case '}':
            set_error(state, REGEX_ERR_INVALID_SYNTAX, "Unexpected special character");
            return NULL;
            
        default:
            return create_char_node(cp, state);
    }
}

// ----------------------------------------------------------------------------
// 15. AST Management (Freeing and Printing)
// ----------------------------------------------------------------------------

void free_regex_ast(RegexNode *node, const regex_allocator* allocator) {
    if (!node) return;

    // This function frees dynamically allocated string data within the AST.
    // The AST nodes themselves are in the arena and are freed all at once.
    switch (node->type) {
        case REGEX_NODE_CHAR_CLASS:
            if (node->data.char_class.set) {
                allocator->free_func(node->data.char_class.set, allocator->user_data);
            }
            break;
        case REGEX_NODE_UNI_PROP:
            if (node->data.uni_prop.prop_name) {
                allocator->free_func(node->data.uni_prop.prop_name, allocator->user_data);
            }
            break;
        case REGEX_NODE_CONCAT:
        case REGEX_NODE_ALTERNATION:
            free_regex_ast(node->data.children.left, allocator);
            free_regex_ast(node->data.children.right, allocator);
            break;
        case REGEX_NODE_QUANTIFIER:
            free_regex_ast(node->data.quantifier.child, allocator);
            break;
        case REGEX_NODE_GROUP:
        case REGEX_NODE_BRESET_GROUP:
            if (node->data.group.name) {
                allocator->free_func(node->data.group.name, allocator->user_data);
            }
            free_regex_ast(node->data.group.child, allocator);
            break;
        case REGEX_NODE_BACKREF:
            if (node->data.backref.ref_name) {
                allocator->free_func(node->data.backref.ref_name, allocator->user_data);
            }
            break;
        case REGEX_NODE_ASSERTION:
            free_regex_ast(node->data.assertion.child, allocator);
            break;
        case REGEX_NODE_CONDITIONAL:
            if (node->data.conditional.cond.type == COND_NAMED && node->data.conditional.cond.data.group_name) {
                allocator->free_func(node->data.conditional.cond.data.group_name, allocator->user_data);
            } else if (node->data.conditional.cond.type == COND_ASSERTION) {
                free_regex_ast(node->data.conditional.cond.data.assertion, allocator);
            }
            free_regex_ast(node->data.conditional.if_true, allocator);
            free_regex_ast(node->data.conditional.if_false, allocator);
            break;
        case REGEX_NODE_SUBROUTINE:
            if (node->data.subroutine.target_name) {
                allocator->free_func(node->data.subroutine.target_name, allocator->user_data);
            }
            break;
        default:
            break;
    }
}

void print_regex_ast_recursive(const RegexNode *node, int indent) {
    if (!node) {
        printf("%*s(epsilon)\n", indent, "");
        return;
    }
    if (node->type == REGEX_NODE_COMMENT) return;

    for (int i = 0; i < indent; ++i) printf("  ");

    switch (node->type) {
        case REGEX_NODE_CHAR:
            if (node->data.codepoint < 128 && isprint(node->data.codepoint)) {
                printf("CHAR: '%c'\n", (char)node->data.codepoint);
            } else {
                printf("CHAR: U+%04X\n", node->data.codepoint);
            }
            break;
        case REGEX_NODE_DOT: printf("DOT: .\n"); break;
        case REGEX_NODE_ANCHOR: printf("ANCHOR: \\%c\n", node->data.anchor_type); break;
        case REGEX_NODE_CHAR_CLASS:
            printf("CHAR_CLASS: [%s%s]\n", node->data.char_class.negated ? "^" : "", node->data.char_class.set);
            break;
        case REGEX_NODE_UNI_PROP:
            printf("UNI_PROP: \\%c{%s}\n", node->data.uni_prop.negated ? 'P' : 'p', node->data.uni_prop.prop_name);
            break;
        case REGEX_NODE_CONCAT:
            printf("CONCAT\n");
            print_regex_ast_recursive(node->data.children.left, indent + 1);
            print_regex_ast_recursive(node->data.children.right, indent + 1);
            break;
        case REGEX_NODE_ALTERNATION:
            printf("ALTERNATION\n");
            print_regex_ast_recursive(node->data.children.left, indent + 1);
            print_regex_ast_recursive(node->data.children.right, indent + 1);
            break;
        case REGEX_NODE_QUANTIFIER: {
            const char *q_type = "unknown";
            switch (node->data.quantifier.quant_type) {
                case QUANT_GREEDY: q_type = "greedy"; break;
                case QUANT_LAZY: q_type = "lazy"; break;
                case QUANT_POSSESSIVE: q_type = "possessive"; break;
            }
            printf("QUANTIFIER {min=%d, max=%d, type=%s}\n",
                   node->data.quantifier.min,
                   node->data.quantifier.max < 0 ? -1 : node->data.quantifier.max,
                   q_type);
            print_regex_ast_recursive(node->data.quantifier.child, indent + 1);
            break;
        }
        case REGEX_NODE_GROUP:
            printf("GROUP (%s%s%s #%d)\n",
                   node->data.group.is_atomic ? "atomic" : (node->data.group.capture_index < 0 ? "non-capturing" : "capture"),
                   node->data.group.name ? ", name=" : "", node->data.group.name ? node->data.group.name : "",
                   node->data.group.capture_index);
            print_regex_ast_recursive(node->data.group.child, indent + 1);
            break;
        case REGEX_NODE_BACKREF:
            if (node->data.backref.ref_name) {
                printf("BACKREF: \\k<%s> (group %d)\n", node->data.backref.ref_name, node->data.backref.ref_index);
            } else {
                printf("BACKREF: \\%d\n", node->data.backref.ref_index);
            }
            break;
        case REGEX_NODE_ASSERTION: {
            const char *typestr = "";
            switch (node->data.assertion.assert_type) {
                case ASSERT_LOOKAHEAD_POS: typestr = "LOOKAHEAD_POS (?=)"; break;
                case ASSERT_LOOKAHEAD_NEG: typestr = "LOOKAHEAD_NEG (?!...)"; break;
                case ASSERT_LOOKBEHIND_POS: typestr = "LOOKBEHIND_POS (?<=...)"; break;
                case ASSERT_LOOKBEHIND_NEG: typestr = "LOOKBEHIND_NEG (?<!)"; break;
            }
            printf("ASSERTION %s\n", typestr);
            print_regex_ast_recursive(node->data.assertion.child, indent + 1);
            break;
        }
        case REGEX_NODE_BRESET_GROUP:
            printf("BRESET_GROUP (?|...)\n");
            print_regex_ast_recursive(node->data.group.child, indent + 1);
            break;
        case REGEX_NODE_CONDITIONAL:
            printf("CONDITIONAL (?(...)...)\n");
            printf("%*sCondition: ", indent + 1, "");
            switch (node->data.conditional.cond.type) {
                case COND_INVALID:
                    printf("INVALID\n");
                    break;
                case COND_NUMERIC:
                    printf("group %d\n", node->data.conditional.cond.data.group_index); break;
                case COND_NAMED:
                    printf("group <%s>\n", node->data.conditional.cond.data.group_name); break;
                case COND_ASSERTION:
                    printf("assertion\n");
                    print_regex_ast_recursive(node->data.conditional.cond.data.assertion, indent + 2); break;
            }
            printf("%*sIf true:\n", indent + 1, "");
            print_regex_ast_recursive(node->data.conditional.if_true, indent + 2);
            if (node->data.conditional.if_false) {
                printf("%*sIf false:\n", indent + 1, "");
                print_regex_ast_recursive(node->data.conditional.if_false, indent + 2);
            }
            break;
        case REGEX_NODE_SUBROUTINE:
            if (node->data.subroutine.is_recursion) {
                printf("SUBROUTINE: (?R)\n");
            } else if (node->data.subroutine.target_name) {
                printf("SUBROUTINE: (?&%s)\n", node->data.subroutine.target_name);
            } else {
                printf("SUBROUTINE: (?%d)\n", node->data.subroutine.target_index);
            }
            break;
        case REGEX_NODE_COMMENT: break; // Already handled
    }
}

void print_regex_ast(const regex_compiled *root) {
    if (!root || !root->ast) { printf("AST is empty.\n"); return; }
    print_regex_ast_recursive(root->ast, 0);
}

// ----------------------------------------------------------------------------
// 16. Main Entry Point and Cleanup
// ----------------------------------------------------------------------------

// A single function to free all resources related to a parse state.
void free_parser_state_resources(ParserState* state) {
    if (!state->arena) return;
    
    const regex_allocator* allocator = &state->arena->allocator;
    
    for (int i = 0; i < state->fixup_count; i++) {
        if (state->fixups[i].name) {
            allocator->free_func(state->fixups[i].name, allocator->user_data);
        }
    }
    if (state->fixups) allocator->free_func(state->fixups, allocator->user_data);
    state->fixups = NULL;
    
    for (int i = 0; i < state->named_group_count; i++) {
        if (state->named_groups[i].name) {
            state->arena->allocator.free_func(state->named_groups[i].name, state->arena->allocator.user_data);
        }
    }
    if (state->named_groups) state->arena->allocator.free_func(state->named_groups, state->arena->allocator.user_data);
    state->named_groups = NULL;
    
    arena_free(state->arena);
    allocator->free_func(state->arena, allocator->user_data);
    state->arena = NULL;
}

static void validate_numeric_backrefs(RegexNode *n, ParserState *st) {
    if (!n || st->has_error) return;
    if (n->type == REGEX_NODE_BACKREF && n->data.backref.ref_name == NULL) {
        int idx = n->data.backref.ref_index;
        if (idx < 1 || idx > st->capture_count) {
            set_error(
              st,
              REGEX_ERR_INVALID_BACKREF,
              "Backreference to undefined group"
            );
            return;
        }
    }
    switch(n->type) {
      case REGEX_NODE_CONCAT:
        validate_numeric_backrefs(n->data.children.left,  st);
        validate_numeric_backrefs(n->data.children.right, st);
        break;
      case REGEX_NODE_ALTERNATION:
        validate_numeric_backrefs(n->data.children.left,  st);
        validate_numeric_backrefs(n->data.children.right, st);
        break;
      case REGEX_NODE_QUANTIFIER:
        validate_numeric_backrefs(n->data.quantifier.child, st);
        break;
      case REGEX_NODE_GROUP:
      case REGEX_NODE_BRESET_GROUP:
        validate_numeric_backrefs(n->data.group.child, st);
        break;
      case REGEX_NODE_ASSERTION:
        validate_numeric_backrefs(n->data.assertion.child, st);
        break;
      case REGEX_NODE_CONDITIONAL:
        validate_numeric_backrefs(n->data.conditional.if_true,  st);
        if (n->data.conditional.if_false)
          validate_numeric_backrefs(n->data.conditional.if_false, st);
        break;
      default:
        break;
    }
}

static RegexNode* regex_parse_internal(
    const char* pattern,
    uint32_t flags,
    const regex_allocator* allocator,
    AstArena** out_arena,
    int* out_capture_count,
    regex_err* error)
{
    *out_arena = NULL;
    *out_capture_count = 0;
    memset(error, 0, sizeof(*error));

    AstArena* arena = allocator->malloc_func(sizeof(AstArena), allocator->user_data);
    if (!arena) {
        error->code = REGEX_ERR_MEMORY;
        error->msg = regex_error_message(REGEX_ERR_MEMORY);
        return NULL;
    }
    memset(arena, 0, sizeof(AstArena));
    arena->allocator = *allocator;

    ParserState state = {
        .pattern = pattern,
        .arena = arena,
        .compile_flags = flags,
        .in_conditional = false
    };
    if (flags & REG_IGNORECASE) state.flags |= REG_IGNORECASE;
    if (flags & REG_MULTILINE)  state.flags |= REG_MULTILINE;
    if (flags & REG_SINGLELINE) state.flags |= REG_SINGLELINE;
    if (flags & REG_EXTENDED)   state.flags |= REG_EXTENDED;
    if (flags & REG_UNGREEDY)   state.flags |= REG_UNGREEDY;

    RegexNode* root = parse_regex(&state);

    if (!state.has_error) {
        process_fixups(&state);
    }

    if (state.has_error) {
        *error = state.error;
        free_parser_state_resources(&state);
        return NULL;
    }

    if (peek_codepoint(&state) != 0) {
        set_error(&state, REGEX_ERR_INVALID_SYNTAX, "Unexpected characters at end of pattern");
        *error = state.error;
        free_parser_state_resources(&state);
        return NULL;
    }

    if (!state.has_error) {
        validate_numeric_backrefs(root, &state);
    }
    if (state.has_error) {
        *error = state.error;
        free_parser_state_resources(&state);
        return NULL;
    }

    // Success
    *out_arena = arena;
    *out_capture_count = state.capture_count;

    // Free temporary lists used only during parsing
    for (int i = 0; i < state.fixup_count; i++) {
        allocator->free_func(state.fixups[i].name, allocator->user_data);
    }
    if (state.fixups) allocator->free_func(state.fixups, allocator->user_data);
    for (int i = 0; i < state.named_group_count; i++) {
        if (state.named_groups[i].name) {
            state.arena->allocator.free_func(state.named_groups[i].name, state.arena->allocator.user_data);
        }
    }
    if (state.named_groups) state.arena->allocator.free_func(state.named_groups, state.arena->allocator.user_data);

    return root;
}

// ----------------------------------------------------------------------------
// 17. New Public API Implementation
// ----------------------------------------------------------------------------

regex_compiled* regex_compile_with_allocator(
    const char* pattern,
    uint32_t flags,
    const regex_allocator* allocator,
    regex_err* error)
{
    regex_err local_error;
    if (!error) {
        error = &local_error;
    }

    if (!pattern || !allocator) {
        error->code = REGEX_ERR_INVALID_SYNTAX;
        error->msg = "Invalid parameters: pattern and allocator must not be NULL";
        return NULL;
    }

    regex_compiled* rx = allocator->malloc_func(sizeof(regex_compiled), allocator->user_data);
    if (!rx) {
        error->code = REGEX_ERR_MEMORY;
        error->msg = regex_error_message(REGEX_ERR_MEMORY);
        return NULL;
    }
    memset(rx, 0, sizeof(*rx));
    rx->allocator = *allocator;
    rx->flags = flags;

    // Stage 1: Parse pattern into AST
    rx->ast = regex_parse_internal(pattern, flags, allocator, &rx->arena, &rx->capture_count, error);

    if (!rx->ast) {
        allocator->free_func(rx, allocator->user_data);
        return NULL;
    }

    // Stage 2: Compile AST to bytecode
    if (compile_regex_to_bytecode(rx, error) != REGEX_OK) {
        regex_free(rx); // This will free ast, arena, etc.
        return NULL;
    }

    return rx;
}

regex_compiled* regex_compile(const char* pattern, uint32_t flags, regex_err* error) {
    return regex_compile_with_allocator(pattern, flags, &default_allocator, error);
}

void regex_free(regex_compiled* rx) {
    if (!rx) return;

    regex_allocator allocator = rx->allocator;

    if (rx->ast && rx->arena) {
        free_regex_ast(rx->ast, &allocator);
        arena_free(rx->arena);
        allocator.free_func(rx->arena, allocator.user_data);
    }

    if (rx->code) {
        allocator.free_func(rx->code, allocator.user_data);
    }

    allocator.free_func(rx, allocator.user_data);
}

void regex_free_match_result(regex_match_result* result, const regex_allocator* alloc) {
    if (!result) return;
    const regex_allocator* allocator = alloc ? alloc : &default_allocator;
    if (result->capture_starts) allocator->free_func(result->capture_starts, allocator->user_data);
    if (result->capture_ends) allocator->free_func(result->capture_ends, allocator->user_data);
}
