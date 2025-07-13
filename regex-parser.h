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

// Regex compilation flags
#define REG_IGNORECASE  0x01
#define REG_MULTILINE   0x02
#define REG_SINGLELINE  0x04
#define REG_EXTENDED    0x08
#define REG_UNGREEDY    0x10

typedef struct Block {
    void *data;
    size_t used;
    size_t cap;
    struct Block *next;
} Block;

typedef struct AstArena {
    Block *blocks;
    size_t total_allocated;
} AstArena;

typedef enum {
    NODE_CHAR,          // Literal character
    NODE_DOT,           // . (any character)
    NODE_ANCHOR,        // ^, $, \A, \z, \b, \B
    NODE_CHAR_CLASS,    // [abc], [^abc], \d, \s, etc.
    NODE_CONCAT,        // ab (sequence)
    NODE_ALTERNATION,   // a|b
    NODE_QUANTIFIER,    // *, +, ?, {m,n}
    NODE_GROUP,         // ( ... ) (capturing or non-capturing)
    NODE_BACKREF,       // \1, \k<name> etc.
    NODE_ASSERTION,     // lookahead/lookbehind assertions
    NODE_COMMENT,       // (?#...) - will be parsed and discarded
    NODE_UNI_PROP,      // Unicode property \p{...}
    NODE_BRESET_GROUP,  // Branch reset group (?|...)
    NODE_CONDITIONAL,   // Conditional pattern (?(cond)yes|no)
    NODE_SUBROUTINE,    // Subroutine call (?R), (?1), (?&name)
} RegexNodeType;

typedef enum {
    ASSERT_LOOKAHEAD_POS,
    ASSERT_LOOKAHEAD_NEG,
    ASSERT_LOOKBEHIND_POS,
    ASSERT_LOOKBEHIND_NEG,
} AssertionType;

typedef enum {
    QUANT_GREEDY,
    QUANT_LAZY,
    QUANT_POSSESSIVE,
} QuantifierType;

typedef enum {
    COND_INVALID = 0,
    COND_NUMERIC,     // (?(1)...)
    COND_NAMED,       // (?(<name>)...)
    COND_ASSERTION,   // (?((?=...))...)
    // Note: The simple (?(assertion)...) form is also common
} ConditionType;

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
        // For NODE_CHAR
        uint32_t codepoint;

        // For NODE_ANCHOR
        char anchor_type;

        // For NODE_CHAR_CLASS
        struct {
            char *set;
            bool negated;
            bool is_posix;
        } char_class;

        // For NODE_CONCAT and NODE_ALTERNATION
        struct {
            struct RegexNode *left;
            struct RegexNode *right;
        } children;

        // For NODE_QUANTIFIER
        struct {
            struct RegexNode *child;
            int min;
            int max;
            QuantifierType quant_type;
        } quantifier;

        // For NODE_GROUP and NODE_BRESET_GROUP
        struct {
            struct RegexNode *child;
            int capture_index;
            char *name;
            bool is_atomic;
            uint32_t enter_flags;
            uint32_t exit_flags;
        } group;

        // For NODE_BACKREF
        struct {
            int ref_index;
            char *ref_name;
        } backref;

        // For NODE_ASSERTION
        struct {
            struct RegexNode *child;
            AssertionType assert_type;
        } assertion;

        // For NODE_UNI_PROP
        struct {
            bool negated;
            char *prop_name;
            uint32_t *bitmap;
        } uni_prop;

        // For NODE_CONDITIONAL
        struct {
            Condition cond;
            struct RegexNode *if_true;
            struct RegexNode *if_false;
        } conditional;

        // For NODE_SUBROUTINE
        struct {
            bool is_recursion;
            int target_index;
            char *target_name;
        } subroutine;
    } data;
} RegexNode;


typedef struct RegexNode RegexNode;
typedef struct AstArena AstArena;

// Function to parse a regex pattern and return an Abstract Syntax Tree (AST)
RegexNode* regex_parse(const char *pattern, uint32_t flags, AstArena **arena, char **error_msg);

// Function to free the memory allocated for the AST
void regex_free_result(RegexNode *node, AstArena *arena);

// Function to print the AST for debugging purposes
void print_regex_ast(const RegexNode *node);

// Cleanup function for property cache
void regex_cleanup_property_cache(void);

#endif // REGEX_PARSER_H
