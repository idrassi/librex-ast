/*
===============================================================================
    regex-parser.h

    Author: Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
    Date: July 13, 2025
    License: MIT

    Description:
    ------------
    Header file for a feature-rich PCRE/Perl-compatible regular expression
    parser in C. Defines the Abstract Syntax Tree (AST) node types, memory
    management structures, and function prototypes for parsing, freeing,
    and debugging regex patterns.

    Features:
    ---------
    - Unicode-aware parsing and character classes
    - Named and numbered capture groups and backreferences
    - Advanced grouping constructs (atomic, branch-reset, conditional, subroutine)
    - Assertions (lookahead, lookbehind)
    - Quantifiers (greedy, lazy, possessive)
    - Arena-based memory management for efficient AST allocation
    - Comprehensive error reporting

    Usage:
    ------
    RegexNode* ast = regex_parse(pattern, flags, &arena, &error_msg);
    if (ast) {
        print_regex_ast(ast);
        regex_free_result(ast, arena);  // Cleanup
    } else {
        printf("Error: %s\n", error_msg);
        free(error_msg);
    }
    regex_cleanup_property_cache();
===============================================================================
*/

#ifndef REGEX_PARSER_H
#define REGEX_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

//==============================================================================
//
//  PUBLIC API
//
//==============================================================================

// Regex compilation flags
#define REG_IGNORECASE  0x01
#define REG_MULTILINE   0x02
#define REG_SINGLELINE  0x04
#define REG_EXTENDED    0x08
#define REG_UNGREEDY    0x10

// Error codes for regex_err
#define REGEX_OK                 0
#define REGEX_ERR_MEMORY         1
#define REGEX_ERR_INVALID_SYNTAX 2
#define REGEX_ERR_INVALID_UTF8   3
#define REGEX_ERR_INVALID_ESCAPE 4
#define REGEX_ERR_INVALID_CLASS  5
#define REGEX_ERR_INVALID_QUANT  6
#define REGEX_ERR_INVALID_GROUP  7
#define REGEX_ERR_INVALID_BACKREF 8
#define REGEX_ERR_INVALID_PROP   9
#define REGEX_ERR_UNMATCHED_PAREN 10
#define REGEX_ERR_INVALID_RANGE  11
#define REGEX_ERR_LOOKBEHIND_VAR 12
#define REGEX_ERR_LOOKBEHIND_LONG 13
#define REGEX_ERR_DUPLICATE_NAME 14
#define REGEX_ERR_UNDEFINED_GROUP 15
#define REGEX_ERR_INVALID_CONDITION 16

// 1.2 Formal error object
typedef struct {
    int code;        // Error code (one of REGEX_ERR_*)
    int pos;         // Character position in pattern string
    int line;        // Line number (1-based)
    int col;         // Column number (1-based)
    const char* msg; // Human-readable error message string
} regex_err;

// 1.3 Allocator pluggability
typedef struct {
    void* (*malloc_func)(size_t size, void* user_data);
    void (*free_func)(void* ptr, void* user_data);
    void* (*realloc_func)(void* ptr, size_t new_size, void* user_data);
    void* user_data; // Opaque pointer passed to allocator functions
} regex_allocator;

// 1.1 Two-stage API: Opaque handle for a compiled regular expression
typedef struct regex_compiled regex_compiled;

// Match result structure (to be used by regex_match)
typedef struct {
    int match_start;
    int match_end;
    int* capture_starts;
    int* capture_ends;
    int capture_count;
} regex_match_result;


// --- Primary API Functions ---

// Compile a regex pattern using a custom allocator.
regex_compiled* regex_compile_with_allocator(
    const char* pattern,
    uint32_t flags,
    const regex_allocator* allocator,
    regex_err* error
);

// Compile a regex pattern using the standard library allocators (malloc, etc.).
regex_compiled* regex_compile(
    const char* pattern,
    uint32_t flags,
    regex_err* error
);

// Free a compiled regex object.
void regex_free(regex_compiled* rx);

// Execute a match against a subject string (currently a placeholder).
int regex_match(
    regex_compiled* rx,
    const char* subject,
    size_t subject_len,
    regex_match_result* result
);

// Free a match result object.
void regex_free_match_result(regex_match_result* result, const regex_allocator* allocator);

// Cleanup function for internal Unicode property cache
void regex_cleanup_property_cache(void);

// --- Utility Functions ---

// Get a standard error message string from an error code.
const char* regex_error_message(int error_code);


//==============================================================================
//
//  PRIVATE INTERNALS - DO NOT USE DIRECTLY
//  (These are exposed for advanced debugging and will change.)
//
//==============================================================================
typedef struct RegexNode RegexNode;
typedef struct AstArena AstArena;

// Print the AST for debugging purposes
void print_regex_ast(const RegexNode* node);

// --- Deprecated legacy API (for backward compatibility) ---
RegexNode* regex_parse(const char *pattern, uint32_t flags, AstArena **arena, char **error_msg);
void regex_free_result(RegexNode *node, AstArena *arena);


// --- Internal data structures ---
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
} AstArena;

typedef enum {
    NODE_CHAR, NODE_DOT, NODE_ANCHOR, NODE_CHAR_CLASS, NODE_CONCAT,
    NODE_ALTERNATION, NODE_QUANTIFIER, NODE_GROUP, NODE_BACKREF, NODE_ASSERTION,
    NODE_COMMENT, NODE_UNI_PROP, NODE_BRESET_GROUP, NODE_CONDITIONAL, NODE_SUBROUTINE
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
        struct { bool negated; char *prop_name; uint32_t *bitmap; } uni_prop;
        struct { Condition cond; struct RegexNode *if_true; struct RegexNode *if_false; } conditional;
        struct { bool is_recursion; int target_index; char *target_name; } subroutine;
    } data;
} RegexNode;


#endif // REGEX_PARSER_H
