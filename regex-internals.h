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

#ifndef REGEX_INTERNALS_H
#define REGEX_INTERNALS_H

#include "regex-parser.h"

//==============================================================================
//
//  PRIVATE INTERNALS - DO NOT USE DIRECTLY
//
//==============================================================================

#define MAX_CACHED_PROPERTIES 32

typedef struct Block {
    void *data;
    size_t used;
    size_t cap;
    struct Block *next;
} Block;

typedef struct AstArena {
    Block *blocks;
    size_t total_allocated;
    regex_allocator allocator;
    struct {
            char* name;  // Or use a dynamic array if needed
            uint32_t* bitmap;
        } property_cache[MAX_CACHED_PROPERTIES];
        int property_cache_count;
} AstArena;

// --- Bytecode Instructions ---
typedef enum {
    I_END, I_CHAR, I_ANY, I_SPLIT, I_JMP, I_SAVE,
    I_RANGE, I_UNIPROP,
    I_BOUND,          /*  word‑boundary  (\b)              */
    I_NBOUND,         /* ­non‑word‑boundary (\B) */
    I_SBOL, I_SEOL,   /*  begin/end of subject (\A, \z)    */
    I_BOL, I_EOL, I_MATCH,
    I_BACKREF, I_GCOND,
    I_ACOND, I_ASUCCESS, I_CALL, I_RETURN,
    I_MARK_ATOMIC, I_CUT_TO_MARK,
    I_LBCOND,
    I_MBOL, I_MEOL
} IType;

typedef struct {
    uint8_t op;
    uintptr_t val;        /* char / index / bit pattern               */
    int32_t  x;          /* addr1 for JMP / SPLIT / sub_pattern_pc     */
    int32_t  y;          /* addr2 for SPLIT / no_branch_pc             */
} Instr;

typedef struct {
    int group_index;
    char *group_name;
    size_t start_pc;
} SubroutineDef;

typedef struct {
    SubroutineDef *defs;
    int count;
    int capacity;
} SubroutineTable;


// --- Internal data structures ---

typedef enum {
    REGEX_NODE_CHAR, REGEX_NODE_DOT, REGEX_NODE_ANCHOR, REGEX_NODE_CHAR_CLASS, REGEX_NODE_CONCAT,
    REGEX_NODE_ALTERNATION, REGEX_NODE_QUANTIFIER, REGEX_NODE_GROUP, REGEX_NODE_BACKREF, REGEX_NODE_ASSERTION,
    REGEX_NODE_COMMENT, REGEX_NODE_UNI_PROP, REGEX_NODE_BRESET_GROUP, REGEX_NODE_CONDITIONAL, REGEX_NODE_SUBROUTINE
} RegexNodeType;

typedef enum {
    ASSERT_LOOKAHEAD_POS, ASSERT_LOOKAHEAD_NEG,
    ASSERT_LOOKBEHIND_POS, ASSERT_LOOKBEHIND_NEG
} AssertionType;

typedef enum { QUANT_GREEDY, QUANT_LAZY, QUANT_POSSESSIVE } QuantifierType;

typedef enum { COND_INVALID = 0, COND_NUMERIC, COND_NAMED, COND_ASSERTION } ConditionType;

typedef struct Condition {
    ConditionType type;
    union {
        int group_index;
        char *group_name;
        struct RegexNode *assertion;
    } data;
} Condition;

typedef struct RegexNode {
    RegexNodeType type;
    int token_start;
    int token_end;
    union {
        uint32_t codepoint;
        char anchor_type;
        struct { char *set; bool negated; bool is_posix; } char_class;
        struct { struct RegexNode *left; struct RegexNode *right; } children;
        struct { struct RegexNode *child; int min; int max; QuantifierType quant_type; } quantifier;
        struct { struct RegexNode *child; int capture_index; char *name; bool is_atomic; uint32_t enter_flags; uint32_t exit_flags; } group;
        struct { int ref_index; char *ref_name; } backref;
        struct { struct RegexNode *child; AssertionType assert_type; } assertion;
        struct { bool negated; char *prop_name; } uni_prop;
        struct { Condition cond; struct RegexNode *if_true; struct RegexNode *if_false; } conditional;
        struct { bool is_recursion; int target_index; char *target_name; } subroutine;
    } data;
} RegexNode;

// The full, internal definition of the compiled regex object.
struct regex_compiled {
    RegexNode* ast;             // The AST (kept for debugging/inspection)
    AstArena* arena;            // Arena for AST and compile-time data
    uint32_t flags;
    int capture_count;
    regex_allocator allocator;

    // --- Pre-compiled Bytecode ---
    Instr* code;                // The compiled bytecode
    size_t pc;                  // Number of instructions in the bytecode
};

// Internal function to perform the AST -> Bytecode compilation step.
int compile_regex_to_bytecode(struct regex_compiled* rx, regex_err* error);

#endif // REGEX_INTERNALS_H
