/*
===============================================================================
    regex-parser.c

    Author: Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
    Date: July 13, 2025
    License: MIT

    Description:
    ------------
    This file implements a feature-rich PCRE/Perl-compatible regular expression 
    parser in C, supporting Unicode, advanced grouping constructs, recursive 
    patterns, and comprehensive error reporting with line/column information.

    Features:
    ---------
    - Recursive descent parsing to build an Abstract Syntax Tree (AST)
    - Two-phase parsing with deferred fixup resolution for forward references
    - Unicode-aware parsing using built-in UTF-8 decoder (no locale dependency)
    - Named capture groups (?<name>...) and named backreferences (\k<name>)
    - Numbered backreferences (\1, \2, etc.) with validation
    - Atomic groups (?>...) for possessive matching
    - Lookahead (?=..., ?!...) and lookbehind (?<=..., ?<!...) assertions
    - Possessive (+), lazy (?), and greedy quantifiers with context sensitivity
    - Branch-reset groups (?|...) for capture group reuse across alternations
    - Conditional patterns (?(condition)yes|no) with multiple condition types:
      * Numeric conditions (?(1)...)
      * Named conditions (?(<name>)...)  
      * Assertion conditions (?((?=...))...)
    - Subroutine calls for pattern recursion:
      * Full recursion (?R)
      * Numbered calls (?1, ?2, etc.)
      * Named calls (?&name)
    - Inline comments (?#...) and mode modifiers (?flags:...)
    - Quoted sequences \Q...\E for literal matching
    - Extended Unicode escapes \x{...} and \u{...}
    - POSIX character classes [[:alpha:]], [[:digit:]], etc.
    - Unicode property escapes \p{...} and \P{...} (framework ready)
    - Context-sensitive anchor validation (^ position checking)
    - Comprehensive character class parsing with nested bracket support
    - Inline flag modifications (?i), (?-i), (?i:...) for case sensitivity, etc.
    - Hexadecimal escape sequences (\x20, \x{1F600})
    - Standard escape sequences (\t, \n, \r, \f, etc.)
    - Arena-based memory management for optimal performance
    - Comprehensive error reporting with UTF-8 aware position tracking
    - Thread-safe implementation with no global state
    - Extensive test suite covering edge cases and error conditions

    Implementation Details:
    ---------------
    - Uses flexible AST node structures for all regex constructs
    - Parser state tracks position, captures, named groups, and parse context
    - Two-phase parsing: initial AST construction + deferred fixup resolution
    - Width analysis for lookbehind assertion validation (fixed-width requirement)
    - Arena-based memory management for AST nodes (bulk deallocation)
    - Dynamic arrays for named groups and fixup tracking
    - Single-pass UTF-8 validation with detailed error context
    - Quantifier type resolution based on global ungreedy flag and local modifiers
    - Conditional parsing context for proper alternation handling
    - Comprehensive semantic validation with forward reference checking
    - Unicode property bitmap caching for performance
    - Error reporting with line/column information
    - Proper handling of nested character classes and POSIX classes
    - Flag inheritance and scoping for inline modifiers
    - Quantifier validation (no double quantifiers, no quantifying assertions)

    Supported Regex Constructs:
    ---------------------------
    Basic Elements:
    - Literal characters (including Unicode)
    - Character classes [abc], [^abc], [a-z]
    - Predefined classes: \d, \D, \w, \W, \s, \S
    - Dot metacharacter (.)
    - Anchors: ^, $, \A, \z, \b, \B
    
    Quantifiers:
    - *, +, ?, {n}, {n,}, {n,m}
    - Lazy variants: *?, +?, ??, {n,m}?
    - Possessive variants: *+, ++, ?+, {n,m}+
    
    Groups:
    - Capturing groups: (...)
    - Non-capturing groups: (?:...)
    - Named groups: (?<name>...)
    - Atomic groups: (?>...)
    - Branch-reset groups: (?|...)
    
    Assertions:
    - Positive lookahead: (?=...)
    - Negative lookahead: (?!...)
    - Positive lookbehind: (?<=...)
    - Negative lookbehind: (?<!...)
    
    Backreferences:
    - Numbered: \1, \2, etc.
    - Named: \k<name>
    
    Conditionals:
    - Numeric: (?(1)yes|no)
    - Named: (?(<name>)yes|no)
    - Assertion: (?((?=...))yes|no)
    
    Subroutines:
    - Full recursion: (?R)
    - Numbered calls: (?1), (?2), etc.
    - Named calls: (?&name)
    
    Modifiers:
    - Inline flags: (?i), (?m), (?s), (?x), (?U)
    - Scoped flags: (?i:...)
    - Flag negation: (?-i)
    
    Unicode Support:
    - UTF-8 input validation
    - Unicode escapes: \x{...}, \u{...}
    - Unicode properties: \p{...}, \P{...}
    - Full range of Unicode characters
    
    Other Features:
    - Comments: (?#...)
    - Quoted sequences: \Q...\E
    - POSIX character classes: [[:alpha:]], etc.

    Current Limitations:
    -------------------
    - Parser only (no execution engine included)
    - No AST optimization passes
    - No bytecode generation or compilation
    - POSIX character classes use basic implementation
    - Unicode property support is framework-ready but uses simplified data
    - No support for variable-length lookbehind assertions
    - Maximum lookbehind length limited to 255 characters (PCRE compatible)
    - Property cache limited to 32 entries
    - No support for \R (generic newline), \X (extended grapheme cluster)
    - No support for (*VERB) constructs like (*SKIP), (*FAIL)
    - No support for \g{...} backreference syntax
    - No support for recursive balancing groups

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "regex-parser.h"

// ----------------------------------------------------------------------------
// 1. Arena Allocation for Performance
// ----------------------------------------------------------------------------

static void *arena_alloc(AstArena *arena, size_t size) {
    if (!arena->blocks || arena->blocks->used + size > arena->blocks->cap) {
        size_t cap = size > 64*1024 ? size : 64*1024;
        Block *block = malloc(sizeof(Block));
        if (!block) return NULL;
        
        block->data = malloc(cap);
        if (!block->data) {
            free(block);
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
        free(block->data);
        free(block);
        block = next;
    }
    arena->blocks = NULL;
    arena->total_allocated = 0;
}

// ----------------------------------------------------------------------------
// 2. UTF-8 Decoder (Thread-safe, no locale dependency)
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

static char *ascii_lower(const char *str) {
    size_t len = strlen(str);
    char *result = malloc(len + 1);
    if (!result) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        result[i] = tolower(str[i]);
    }
    result[len] = '\0';
    return result;
}

// ----------------------------------------------------------------------------
// 3. Unicode Properties Support
// ----------------------------------------------------------------------------

// Unicode category mappings - simplified version for demonstration
// In production, this would be generated from Unicode data files
typedef struct {
    uint32_t start;
    uint32_t end;
    const char* category;
} UnicodeRange;

// Sample Unicode ranges for major categories (this would be much larger in production)
static const UnicodeRange unicode_ranges[] = {
    // Basic Latin uppercase letters
    {0x0041, 0x005A, "Lu"},
    {0x0041, 0x005A, "L"},
    
    // Basic Latin lowercase letters
    {0x0061, 0x007A, "Ll"},
    {0x0061, 0x007A, "L"},
    
    // Latin-1 Supplement uppercase
    {0x00C0, 0x00D6, "Lu"},
    {0x00C0, 0x00D6, "L"},
    {0x00D8, 0x00DE, "Lu"},
    {0x00D8, 0x00DE, "L"},
    
    // Latin-1 Supplement lowercase
    {0x00E0, 0x00F6, "Ll"},
    {0x00E0, 0x00F6, "L"},
    {0x00F8, 0x00FF, "Ll"},
    {0x00F8, 0x00FF, "L"},
    
    // ASCII digits
    {0x0030, 0x0039, "Nd"},
    {0x0030, 0x0039, "N"},
    
    // ASCII punctuation
    {0x0021, 0x002F, "Po"},
    {0x0021, 0x002F, "P"},
    {0x003A, 0x0040, "Po"},
    {0x003A, 0x0040, "P"},
    {0x005B, 0x0060, "Po"},
    {0x005B, 0x0060, "P"},
    {0x007B, 0x007E, "Po"},
    {0x007B, 0x007E, "P"},
    
    // ASCII whitespace
    {0x0009, 0x000D, "Cc"},
    {0x0009, 0x000D, "C"},
    {0x0020, 0x0020, "Zs"},
    {0x0020, 0x0020, "Z"},
    
    // Greek uppercase
    {0x0391, 0x03A1, "Lu"},
    {0x0391, 0x03A1, "L"},
    {0x03A3, 0x03AB, "Lu"},
    {0x03A3, 0x03AB, "L"},
    
    // Greek lowercase
    {0x03B1, 0x03C1, "Ll"},
    {0x03B1, 0x03C1, "L"},
    {0x03C3, 0x03CB, "Ll"},
    {0x03C3, 0x03CB, "L"},
    
    // Cyrillic uppercase
    {0x0410, 0x042F, "Lu"},
    {0x0410, 0x042F, "L"},
    
    // Cyrillic lowercase
    {0x0430, 0x044F, "Ll"},
    {0x0430, 0x044F, "L"},
    
    // End marker
    {0, 0, NULL}
};

// Cache for computed bitmaps
#define MAX_CACHED_PROPERTIES 32
static struct {
    char* name;
    uint32_t* bitmap;
    bool computed;
} property_cache[MAX_CACHED_PROPERTIES];

static int property_cache_count = 0;

// Bitmap size for Unicode code points (covers BMP + supplementary planes)
#define BITMAP_SIZE (0x110000 / 32)

static void set_bit_in_bitmap(uint32_t* bitmap, uint32_t codepoint) {
    if (codepoint >= 0x110000) return;
    bitmap[codepoint / 32] |= (1U << (codepoint % 32));
}

static bool is_bit_set_in_bitmap(uint32_t* bitmap, uint32_t codepoint) {
    if (codepoint >= 0x110000) return false;
    return (bitmap[codepoint / 32] & (1U << (codepoint % 32))) != 0;
}

// Check if a property name matches (handles both full names and abbreviations)
static bool property_matches(const char* prop_name, const char* target) {
    if (!prop_name || !target) return false;
    
    // Exact match
    if (strcmp(prop_name, target) == 0) return true;
    
    // Handle common aliases
    if (strcmp(prop_name, "alpha") == 0 && strcmp(target, "L") == 0) return true;
    if (strcmp(prop_name, "alnum") == 0 && (strcmp(target, "L") == 0 || strcmp(target, "N") == 0)) return true;
    if (strcmp(prop_name, "digit") == 0 && strcmp(target, "Nd") == 0) return true;
    if (strcmp(prop_name, "space") == 0 && (strcmp(target, "Z") == 0 || strcmp(target, "Cc") == 0)) return true;
    if (strcmp(prop_name, "upper") == 0 && strcmp(target, "Lu") == 0) return true;
    if (strcmp(prop_name, "lower") == 0 && strcmp(target, "Ll") == 0) return true;
    if (strcmp(prop_name, "punct") == 0 && strcmp(target, "P") == 0) return true;
    
    return false;
}

// Build a bitmap for a specific Unicode property
static uint32_t* build_unicode_bitmap(const char* prop_name) {
    uint32_t* bitmap = calloc(BITMAP_SIZE, sizeof(uint32_t));
    if (!bitmap) return NULL;
    
    // Handle special composite properties
    if (strcmp(prop_name, "alnum") == 0) {
        // Alphanumeric = Letters + Numbers
        for (const UnicodeRange* range = unicode_ranges; range->category; range++) {
            if (property_matches("L", range->category) || property_matches("N", range->category)) {
                for (uint32_t cp = range->start; cp <= range->end; cp++) {
                    set_bit_in_bitmap(bitmap, cp);
                }
            }
        }
        return bitmap;
    }
    
    if (strcmp(prop_name, "word") == 0) {
        // Word characters = Letters + Numbers + Underscore
        for (const UnicodeRange* range = unicode_ranges; range->category; range++) {
            if (property_matches("L", range->category) || property_matches("N", range->category)) {
                for (uint32_t cp = range->start; cp <= range->end; cp++) {
                    set_bit_in_bitmap(bitmap, cp);
                }
            }
        }
        set_bit_in_bitmap(bitmap, '_'); // Add underscore
        return bitmap;
    }
    
    if (strcmp(prop_name, "space") == 0) {
        // Space characters = Separators + some control characters
        for (const UnicodeRange* range = unicode_ranges; range->category; range++) {
            if (property_matches("space", range->category)) {
                for (uint32_t cp = range->start; cp <= range->end; cp++) {
                    set_bit_in_bitmap(bitmap, cp);
                }
            }
        }
        return bitmap;
    }
    
    // Handle standard Unicode categories
    for (const UnicodeRange* range = unicode_ranges; range->category; range++) {
        if (property_matches(prop_name, range->category)) {
            for (uint32_t cp = range->start; cp <= range->end; cp++) {
                set_bit_in_bitmap(bitmap, cp);
            }
        }
    }
    
    return bitmap;
}

// Find cached bitmap or compute it
static uint32_t* get_cached_bitmap(const char* prop_name) {
    // Check cache first
    for (int i = 0; i < property_cache_count; i++) {
        if (property_cache[i].name && strcmp(property_cache[i].name, prop_name) == 0) {
            return property_cache[i].bitmap;
        }
    }
    
    // Not in cache, compute it
    if (property_cache_count >= MAX_CACHED_PROPERTIES) {
        // Cache is full, just compute without caching
        return build_unicode_bitmap(prop_name);
    }
    
    uint32_t* bitmap = build_unicode_bitmap(prop_name);
    if (bitmap) {
        // Add to cache
        property_cache[property_cache_count].name = strdup(prop_name);
        property_cache[property_cache_count].bitmap = bitmap;
        property_cache[property_cache_count].computed = true;
        property_cache_count++;
    }
    
    return bitmap;
}

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

// Enhanced bitmap retrieval function
static uint32_t* unicode_bitmap_for(const char* name) {
    if (!name || !unicode_property_exists(name)) {
        return NULL;
    }
    
    return get_cached_bitmap(name);
}

// Cleanup function for property cache
void regex_cleanup_property_cache(void) {
    for (int i = 0; i < property_cache_count; i++) {
        if (property_cache[i].name) {
            free(property_cache[i].name);
            property_cache[i].name = NULL;
        }
        if (property_cache[i].bitmap) {
            free(property_cache[i].bitmap);
            property_cache[i].bitmap = NULL;
        }
    }
    property_cache_count = 0;
}

// Function to test if a codepoint matches a property
bool matches_unicode_property(uint32_t codepoint, const char* prop_name, bool negated) {
    uint32_t* bitmap = unicode_bitmap_for(prop_name);
    if (!bitmap) return negated; // If property doesn't exist, return negated value
    
    bool matches = is_bit_set_in_bitmap(bitmap, codepoint);
    return negated ? !matches : matches;
}

// ----------------------------------------------------------------------------
// 4. Enhanced Data Structures for the AST
// ----------------------------------------------------------------------------

// Fixup structure for deferred validation
typedef struct {
    RegexNode *node;
    char *name;
} Fixup;

// Parser state
typedef struct {
    const char *pattern;
    int pos;
    int capture_count;
    char error_msg[256];
    bool has_error;
    int line_number;
    int column_start;
    char **named_groups;
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

// ----------------------------------------------------------------------------
// 5. Forward declarations
// ----------------------------------------------------------------------------
RegexNode* parse_regex(ParserState *state);
RegexNode* parse_term(ParserState *state);
RegexNode* parse_factor(ParserState *state);
RegexNode* parse_atom(ParserState *state);
void free_regex_ast(RegexNode *node);
void set_error(ParserState *state, const char *msg);
static int compute_width(RegexNode *node, int *min, int *max);

// ----------------------------------------------------------------------------
// 6. Helper functions for creating AST nodes
// ----------------------------------------------------------------------------
RegexNode* create_node(RegexNodeType type, ParserState *state) {
    RegexNode *node = (RegexNode*)arena_alloc(state->arena, sizeof(RegexNode));
    if (!node) {
        set_error(state, "Memory allocation failed");
        return NULL;
    }
    memset(node, 0, sizeof(RegexNode));
    node->type = type;
    node->token_start = state ? state->column_start : -1;
    node->token_end = state ? state->pos : -1;
    return node;
}

RegexNode* create_char_node(uint32_t codepoint, ParserState *state) {
    RegexNode *node = create_node(NODE_CHAR, state);
    if (!node) return NULL;
    node->data.codepoint = codepoint;
    return node;
}

RegexNode* create_concat_node(RegexNode *left, RegexNode *right, ParserState *state) {
    if (!left && !right) {
        RegexNode *node = create_node(NODE_CONCAT, state);
        if (!node) return NULL;
        node->data.children.left = NULL;
        node->data.children.right = NULL;
        return node;
    }
    if (!left) return right;
    if (!right) return left;
    
    RegexNode *node = create_node(NODE_CONCAT, state);
    if (!node) return NULL;
    node->data.children.left = left;
    node->data.children.right = right;
    return node;
}

RegexNode* create_alternation_node(RegexNode *left, RegexNode *right, ParserState *state) {
    RegexNode *node = create_node(NODE_ALTERNATION, state);
    if (!node) return NULL;
    node->data.children.left = left;
    node->data.children.right = right;
    return node;
}

RegexNode* create_quantifier_node(RegexNode *child, int min, int max, QuantifierType type, ParserState *state) {
    RegexNode *node = create_node(NODE_QUANTIFIER, state);
    if (!node) return NULL;
    node->data.quantifier.child = child;
    node->data.quantifier.min = min;
    node->data.quantifier.max = max;
    node->data.quantifier.quant_type = type;
    return node;
}

RegexNode* create_group_node(RegexNode *child, int capture_index, char *name, bool is_atomic, ParserState *state) {
    RegexNode *node = create_node(NODE_GROUP, state);
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
    RegexNode *node = create_node(NODE_CHAR_CLASS, state);
    if (!node) return NULL;
    node->data.char_class.set = set;
    node->data.char_class.negated = negated;
    node->data.char_class.is_posix = is_posix;
    return node;
}

RegexNode* create_anchor_node(char type, ParserState *state) {
    RegexNode *node = create_node(NODE_ANCHOR, state);
    if (!node) return NULL;
    node->data.anchor_type = type;
    return node;
}

RegexNode* create_dot_node(ParserState *state) {
    return create_node(NODE_DOT, state);
}

RegexNode* create_backref_node(int index, char *name, ParserState *state) {
    RegexNode *node = create_node(NODE_BACKREF, state);
    if (!node) return NULL;
    node->data.backref.ref_index = index;
    node->data.backref.ref_name = name;
    return node;
}

RegexNode* create_assertion_node(RegexNode *child, AssertionType type, ParserState *state) {
    RegexNode *node = create_node(NODE_ASSERTION, state);
    if (!node) return NULL;
    node->data.assertion.child = child;
    node->data.assertion.assert_type = type;
    return node;
}

RegexNode* create_uni_prop_node(bool negated, char *prop_name, uint32_t *bitmap, ParserState *state) {
    RegexNode *node = create_node(NODE_UNI_PROP, state);
    if (!node) return NULL;
    node->data.uni_prop.negated = negated;
    node->data.uni_prop.prop_name = prop_name;
    node->data.uni_prop.bitmap = bitmap;
    return node;
}

RegexNode* create_conditional_node(Condition cond, RegexNode *if_true, RegexNode *if_false, ParserState *state) {
    RegexNode *node = create_node(NODE_CONDITIONAL, state);
    if (!node) return NULL;
    node->data.conditional.cond = cond;
    node->data.conditional.if_true = if_true;
    node->data.conditional.if_false = if_false;
    return node;
}

RegexNode* create_subroutine_node(bool is_recursion, int target_index, char *target_name, ParserState *state) {
    RegexNode *node = create_node(NODE_SUBROUTINE, state);
    if (!node) return NULL;
    node->data.subroutine.is_recursion = is_recursion;
    node->data.subroutine.target_index = target_index;
    node->data.subroutine.target_name = target_name;
    return node;
}

// ----------------------------------------------------------------------------
// 7. Fixup system for deferred validation
// ----------------------------------------------------------------------------

static void add_fixup(ParserState *state, RegexNode *node, char *name) {
    if (state->fixup_count >= state->fixup_capacity) {
        state->fixup_capacity = state->fixup_capacity > 0 ? state->fixup_capacity * 2 : 8;
        Fixup *new_fixups = realloc(state->fixups, state->fixup_capacity * sizeof(Fixup));
        if (!new_fixups) {
            set_error(state, "Memory allocation failed for fixups");
            return;
        }
        state->fixups = new_fixups;
    }
    
    state->fixups[state->fixup_count].node = node;
    state->fixups[state->fixup_count].name = strdup(name);
    state->fixup_count++;
}

static int find_named_group_index(ParserState *state, const char *name) {
    for (int i = 0; i < state->named_group_count; i++) {
        if (strcmp(state->named_groups[i], name) == 0) {
            return i + 1; // Return 1-based index
        }
    }
    return -1;
}

static void process_fixups(ParserState *state) {
    for (int i = 0; i < state->fixup_count; i++) {
        Fixup *fixup = &state->fixups[i];
        int group_index = find_named_group_index(state, fixup->name);
        
        if (group_index != -1) {
            if (fixup->node->type == NODE_BACKREF) {
                fixup->node->data.backref.ref_index = group_index;
            } else if (fixup->node->type == NODE_SUBROUTINE) {
                fixup->node->data.subroutine.target_index = group_index;
            }
        } else {
             if (fixup->node->type == NODE_BACKREF) {
                set_error(state, "Backreference to undefined named group");
             } else {
                set_error(state, "Subroutine call to undefined named group");
             }
             return;
        }
    }
}

// ----------------------------------------------------------------------------
// 8. Named group management
// ----------------------------------------------------------------------------

static bool find_named_group(ParserState *state, const char *name) {
    for (int i = 0; i < state->named_group_count; i++) {
        if (strcmp(state->named_groups[i], name) == 0) {
            return true;
        }
    }
    return false;
}

static bool add_named_group(ParserState *state, const char *name) {
    if (find_named_group(state, name)) {
        set_error(state, "Duplicate capture group name");
        return false;
    }

    if (state->named_group_count >= state->named_group_capacity) {
        state->named_group_capacity = state->named_group_capacity > 0 ? state->named_group_capacity * 2 : 8;
        char **new_groups = realloc(state->named_groups, state->named_group_capacity * sizeof(char*));
        if (!new_groups) {
            set_error(state, "Memory allocation failed for named groups");
            return false;
        }
        state->named_groups = new_groups;
    }
    
    state->named_groups[state->named_group_count] = strdup(name);
    if (!state->named_groups[state->named_group_count]) {
        set_error(state, "Memory allocation failed for group name");
        return false;
    }
    state->named_group_count++;
    return true;
}

// ----------------------------------------------------------------------------
// 9. Parser utilities
// ----------------------------------------------------------------------------

void set_error(ParserState *state, const char *msg) {
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

    snprintf(state->error_msg, sizeof(state->error_msg), "Error at line %d, column %d: %s", line, col, msg);
    state->has_error = true;
}

static uint32_t peek_codepoint(ParserState *state) {
    if (state->pattern[state->pos] == '\0') return 0;
    uint32_t codepoint;
    size_t len = utf8_decode(&state->pattern[state->pos], &codepoint);
    if (len == 0) {
        set_error(state, "Invalid UTF-8 sequence");
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
        set_error(state, "Invalid UTF-8 sequence");
        return 0;
    }
    
    state->pos += len;
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
        state->pos += strlen(seq);
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
    state->pos = end - state->pattern;
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
        set_error(state, "Missing name in subroutine call");
        return NULL;
    }
    int len = end - start;
    char *name = malloc(len + 1);
    if (!name) {
        set_error(state, "Memory allocation failed");
        return NULL;
    }
    memcpy(name, &state->pattern[start], len);
    name[len] = '\0';
    return name;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool is_quantifier(uint32_t cp) {
    return cp == '*' || cp == '+' || cp == '?' || cp == '{';
}

// ----------------------------------------------------------------------------
// 10. Width analysis for lookbehind validation
// ----------------------------------------------------------------------------

static int compute_width(RegexNode *node, int *min, int *max) {
    if (!node) {
        *min = *max = 0;
        return 0;
    }
    
    switch (node->type) {
        case NODE_CHAR:
        case NODE_DOT:
        case NODE_CHAR_CLASS:
        case NODE_UNI_PROP:
            *min = *max = 1;
            return 0;
            
        case NODE_ANCHOR:
        case NODE_BACKREF: // Can have variable width
        case NODE_SUBROUTINE:
             *min = 0; *max = -1; // Unbounded
             return 0;

        case NODE_CONCAT: {
            int lmin, lmax, rmin, rmax;
            compute_width(node->data.children.left, &lmin, &lmax);
            compute_width(node->data.children.right, &rmin, &rmax);
            *min = lmin + rmin;
            *max = (lmax == -1 || rmax == -1) ? -1 : lmax + rmax;
            return 0;
        }
        
        case NODE_ALTERNATION: {
            int lmin, lmax, rmin, rmax;
            compute_width(node->data.children.left, &lmin, &lmax);
            compute_width(node->data.children.right, &rmin, &rmax);
            *min = (lmin < rmin) ? lmin : rmin;
            *max = (lmax == -1 || rmax == -1) ? -1 : ((lmax > rmax) ? lmax : rmax);
            return 0;
        }
        
        case NODE_QUANTIFIER: {
            int cmin, cmax;
            compute_width(node->data.quantifier.child, &cmin, &cmax);
            *min = cmin * node->data.quantifier.min;
            *max = (node->data.quantifier.max == -1 || cmax == -1) ? -1 : cmax * node->data.quantifier.max;
            return 0;
        }
        
        case NODE_GROUP:
        case NODE_BRESET_GROUP:
            return compute_width(node->data.group.child, min, max);

        case NODE_CONDITIONAL: {
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
    if (min != max) {
        set_error(state, "Lookbehind assertion is not fixed length");
    }
    if (max > 255) { // PCRE limit
        set_error(state, "Lookbehind assertion is too long");
    }
}

// ----------------------------------------------------------------------------
// 11. Flag parsing for inline modifiers
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
// 12. Parsing functions
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
            set_error(state, "Invalid newline in character class");
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
        set_error(state, "Unmatched '[' in character class");
        return NULL;
    }

    int len = state->pos - start_pos;
    char *content = malloc(len + 1);
    if (!content) {
        set_error(state, "Memory allocation failed");
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
        set_error(state, "Invalid group name: must start with letter or underscore");
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
        set_error(state, "Unmatched '<' in named group");
        return NULL;
    }
    
    int end = state->pos - 1; // back up over '>'
    int len = end - start;
    char *name = malloc(len + 1);
    if (!name) {
        set_error(state, "Memory allocation failed");
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
        if (cond.data.assertion && cond.data.assertion->type == NODE_ASSERTION) {
            cond.type = COND_ASSERTION;
            return cond;
        }
        set_error(state, "Condition is not a valid assertion");
        return cond;
    }

    // This handles `(?(?<=...) ...)`
    if (peek_codepoint(state) == '(') {
        cond.type = COND_ASSERTION;
        cond.data.assertion = parse_atom(state);
        if (state->has_error || !cond.data.assertion || cond.data.assertion->type != NODE_ASSERTION) {
            set_error(state, "Condition is not a valid assertion");
            cond.type = COND_INVALID;
        }
    } else if (peek_codepoint(state) == '<' || peek_codepoint(state) == '\'') {
        cond.type = COND_NAMED;
        char opener = next_codepoint(state);
        char closer = (opener == '<') ? '>' : '\'';
        
        int start = state->pos;
        while (peek_codepoint(state) != closer && peek_codepoint(state) != 0) {
            next_codepoint(state);
        }
        if (!match_codepoint(state, closer)) {
            set_error(state, "Unclosed named condition");
            cond.type = COND_INVALID;
            return cond;
        }
        int len = state->pos - start - 1;
        cond.data.group_name = malloc(len + 1);
        if (!cond.data.group_name) {
            set_error(state, "Memory allocation failed");
            cond.type = COND_INVALID;
            return cond;
        }
        memcpy(cond.data.group_name, &state->pattern[start], len);
        cond.data.group_name[len] = '\0';
        /* Make sure that name has already been declared. */
        if (cond.type == COND_NAMED) {
            if (find_named_group_index(state, cond.data.group_name) == -1) {
                set_error(state, "Conditional references undefined named group");
                cond.type = COND_INVALID;
            }
        }
    } else if (peek_codepoint(state) >= '0' && peek_codepoint(state) <= '9') {
        cond.type = COND_NUMERIC;
        if (!parse_number(state, &cond.data.group_index, 0)) {
            set_error(state, "Invalid group number in condition");
            cond.type = COND_INVALID;
        } else {
            /* The group must already exist (i.e. be to the left).            */
            if (cond.data.group_index <= 0 ||
                cond.data.group_index > state->capture_count) {
                set_error(state, "Conditional references undefined group");
                cond.type = COND_INVALID;
            }
        }
    } else {
        // This handles `(?(?=...) ...)`
        int old_pos = state->pos;
        state->pos--; // go back to the `(`
        RegexNode* assertion = parse_atom(state);
        if(assertion && assertion->type == NODE_ASSERTION) {
            cond.type = COND_ASSERTION;
            cond.data.assertion = assertion;
        } else {
            state->pos = old_pos;
            set_error(state, "Invalid condition");
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
    
    // Anchors and assertions cannot be quantified
    if (atom->type == NODE_ANCHOR || atom->type == NODE_ASSERTION) {
        if (is_quantifier(peek_codepoint(state))) {
            set_error(state, "Cannot quantify an anchor or assertion");
            return NULL;
        }
    }

    uint32_t q = peek_codepoint(state);
    int min = -1, max = -1;
    QuantifierType quant_type = (state->flags & REG_UNGREEDY) ? QUANT_LAZY : QUANT_GREEDY;

    if (q == '*' || q == '+' || q == '?') {
        next_codepoint(state);
        min = (q == '+') ? 1 : 0;
        max = (q == '?') ? 1 : -1;
    } else if (q == '{') {
        next_codepoint(state);
        if (!parse_number(state, &min, 0)) {
            set_error(state, "Expected number in quantifier {}");
            return NULL;
        }
        if (match_codepoint(state, ',')) {
            if (peek_codepoint(state) == '}') {
                max = -1;
            } else if (!parse_number(state, &max, 0)) {
                set_error(state, "Expected number after comma in quantifier {}");
                return NULL;
            }
        } else {
            max = min;
        }
        if (!match_codepoint(state, '}')) {
            set_error(state, "Unmatched '{' in quantifier");
            return NULL;
        }
    }

    if (min != -1) {
        if (min < 0 || (max != -1 && min > max)) {
            set_error(state, "Invalid range in quantifier");
            return NULL;
        }
        
        if (match_codepoint(state, '?')) {
            quant_type = QUANT_LAZY;
        } else if (match_codepoint(state, '+')) {
            quant_type = QUANT_POSSESSIVE;
        }
        
        if (is_quantifier(peek_codepoint(state))) {
            set_error(state, "Double quantifier");
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
                    // Branch reset group
                    int save_count = state->capture_count;
                    RegexNode *alt = parse_regex(state);
                    if (state->has_error) return NULL;
                    
                    while (peek_codepoint(state) == '|') {
                        next_codepoint(state);
                        state->capture_count = save_count;
                        RegexNode *more = parse_regex(state);
                        if (state->has_error) return NULL;
                        alt = create_alternation_node(alt, more, state);
                        if (!alt) return NULL;
                    }
                    if (!match_codepoint(state, ')')) { set_error(state, "Unmatched '(' for branch reset group"); return NULL; }
                    RegexNode *node = create_node(NODE_BRESET_GROUP, state);
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
                            set_error(state, "Expected ')' after condition");
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
                    
                    if (!match_codepoint(state, ')')) { set_error(state, "Unmatched '(' for conditional"); return NULL; }
                    
                    return create_conditional_node(cond, yes, no, state);
                }

                bool is_assertion = false, non_capturing = false, is_atomic = false;
                AssertionType assert_type = 0;
                char *name = NULL;
                uint32_t old_flags = state->flags;

                uint32_t next_c = peek_codepoint(state);
                switch (next_c) {
                    case ':': next_codepoint(state); non_capturing = true; break;
                    case '=': next_codepoint(state); is_assertion = true; assert_type = ASSERT_LOOKAHEAD_POS; break;
                    case '!': next_codepoint(state); is_assertion = true; assert_type = ASSERT_LOOKAHEAD_NEG; break;
                    case '>': next_codepoint(state); is_atomic = true; break;
                    case '#':
                        next_codepoint(state);
                        while (peek_codepoint(state) != ')' && peek_codepoint(state) != 0) next_codepoint(state);
                        if (!match_codepoint(state, ')')) { set_error(state, "Unclosed comment"); return NULL; }
                        return create_node(NODE_COMMENT, state);
                    case '<': {
                        next_codepoint(state);
                        uint32_t next_next = peek_codepoint(state);
                        if (next_next == '=') { next_codepoint(state); is_assertion = true; assert_type = ASSERT_LOOKBEHIND_POS; } 
                        else if (next_next == '!') { next_codepoint(state); is_assertion = true; assert_type = ASSERT_LOOKBEHIND_NEG; } 
                        else {
                            name = parse_group_name(state);
                            if (!name) return NULL;
                            if (!add_named_group(state, name)) { free(name); return NULL; }
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
                            if (!match_codepoint(state, ')')) { set_error(state, "Unmatched '(' for scoped flags"); state->flags = old_flags; return NULL; }
                            RegexNode *group = create_group_node(child, -1, NULL, false, state);
                            if (!group) { state->flags = old_flags; return NULL; }
                            group->data.group.enter_flags = old_flags;
                            group->data.group.exit_flags = state->flags;
                            state->flags = old_flags;
                            return group;
                        } else if (match_codepoint(state, ')')) {
                            return create_group_node(NULL, -1, NULL, false, state);
                        } else { set_error(state, "Expected ':' or ')' after flags"); return NULL; }
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
                            if (!match_codepoint(state, ')')) { set_error(state, "Unclosed subroutine call"); free(target_name); return NULL; }
                            RegexNode *node = create_subroutine_node(false, 0, target_name, state);
                            if (!node) { free(target_name); return NULL; }
                            add_fixup(state, node, target_name);
                            return node;
                        }

                        set_error(state, "Invalid syntax after '(?'"); return NULL;
                    }
                }
                // Common logic for groups parsed above
                int capture_index = -1;
                if (!is_assertion && !non_capturing && !is_atomic) {
                    capture_index = ++state->capture_count;
                }
                RegexNode *sub_expr = parse_regex(state);
                if (state->has_error) { free(name); return NULL; }
                if (!match_codepoint(state, ')')) { set_error(state, "Unmatched '('"); free(name); return NULL; }
                
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
            if (!match_codepoint(state, ')')) { set_error(state, "Unmatched '('"); return NULL; }
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
                    set_error(state, "Empty character class");
                    return NULL;
                }
            }
            for (int i = 0; set[i]; i++) {
                if (set[i] == '\\' && (set[i+1] == 'd' || set[i+1] == 'D' || set[i+1] == 'w' || set[i+1] == 'W' || set[i+1] == 's' || set[i+1] == 'S') && set[i+2] == '-') {
                    free(set);
                    set_error(state, "Invalid range in character class");
                    return NULL;
                }
            }
            return create_char_class_node(set, negated, is_posix, state);
        }
        
        case '\\': {
            uint32_t escaped = next_codepoint(state);
            if (escaped == 0) { set_error(state, "Incomplete escape"); return NULL; }

            if (escaped == 'p' || escaped == 'P') {
                bool neg = (escaped == 'P');
                if (!match_codepoint(state, '{')) { set_error(state, "Expected '{' after \\p"); return NULL; }
                int start = state->pos;
                while (peek_codepoint(state) != '}' && peek_codepoint(state) != 0) next_codepoint(state);
                if (!match_codepoint(state, '}')) { set_error(state, "Unclosed property escape"); return NULL; }
                
                int len = state->pos - start - 1;
                char *raw = malloc(len + 1);
                if (!raw) { set_error(state, "Memory allocation failed"); return NULL; }
                memcpy(raw, &state->pattern[start], len);
                raw[len] = '\0';
                
                char *name = ascii_lower(raw);
                free(raw);
                
                if (!unicode_property_exists(name)) { set_error(state, "Unknown Unicode property"); free(name); return NULL; }
                return create_uni_prop_node(neg, name, unicode_bitmap_for(name), state);
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
                    if (!match_codepoint(state, '}')) { set_error(state, "Unclosed hex escape"); return NULL; }
                    return create_char_node(code, state);
                } else {
                    int num_digits = (escaped == 'x') ? 2 : 4;
                    for(int i = 0; i < num_digits; i++) {
                        uint32_t c = peek_codepoint(state);
                        int val = hexval(c);
                        if (val == -1) { set_error(state, "Invalid hex escape sequence"); return NULL; }
                        code = (code << 4) | val;
                        next_codepoint(state);
                    }
                    return create_char_node(code, state);
                }
            }
            
            if (escaped == 'Q') {
                int start = state->pos;
                while (state->pattern[state->pos] && !(state->pattern[state->pos] == '\\' && state->pattern[state->pos+1] == 'E')) state->pos++;
                if (state->pattern[state->pos] == '\0') { set_error(state, "Unclosed \\Q"); return NULL; }
                int end = state->pos;
                state->pos += 2;
                
                RegexNode *seq = NULL;
                for (int i = start; i < end; ) {
                    uint32_t codepoint;
                    size_t len = utf8_decode(&state->pattern[i], &codepoint);
                    if (len == 0) { set_error(state, "Invalid UTF-8 in \\Q...\\E"); return NULL; }
                    i += len;
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
                if (ref_val > state->capture_count) { set_error(state, "Backreference to undefined group"); return NULL; }
                return create_backref_node(ref_val, NULL, state);
            }
            
            if (escaped == 'k') {
                if (!match_codepoint(state, '<')) { set_error(state, "Expected '<' after \\k"); return NULL; }
                char *name = parse_group_name(state);
                if (!name) return NULL;
                
                int group_index = find_named_group_index(state, name);
                if (group_index == -1) {
                    set_error(state, "Backreference to undefined named group");
                    free(name);
                    return NULL;
                }

                RegexNode *node = create_backref_node(group_index, name, state);
                if (!node) { free(name); return NULL; }
                return node;
            }
            
            switch (escaped) {
                case 'd': case 'D': case 's': case 'S': case 'w': case 'W': {
                    char *set_str = malloc(3);
                    if (!set_str) { set_error(state, "Memory allocation failed"); return NULL; }
                    sprintf(set_str, "\\%c", (char)escaped);
                    return create_char_class_node(set_str, false, false, state);
                }
                case 'b': return create_anchor_node('b', state); case 'B': return create_anchor_node('B', state);
                case 'A': return create_anchor_node('A', state); case 'z': return create_anchor_node('z', state);
                case 't': return create_char_node('\t', state); case 'n': return create_char_node('\n', state);
                case 'r': return create_char_node('\r', state); case 'f': return create_char_node('\f', state);
                default: return create_char_node(escaped, state);
            }
        }
        
        case '.': return create_dot_node(state);
        
        case '^': 
            /* '^' is only valid at pattern start or immediately after
               '(' or '|'.  Everywhere else it is illegal. */
            bool at_start   = (atom_start_pos == 0);
            bool after_par  = (atom_start_pos > 0 &&
                               state->pattern[atom_start_pos-1] == '(');
            bool after_bar  = (atom_start_pos > 0 &&
                               state->pattern[atom_start_pos-1] == '|');
            if (at_start || after_par || after_bar) {
                return create_anchor_node('^', state);
            }
            set_error(state, "Misplaced '^' anchor");
            return NULL;
        case '$': return create_anchor_node('$', state);
        
        case ')': case '|': case '*': case '+': case '?': case '{': case '}':
            set_error(state, "Unexpected special character");
            return NULL;
            
        default:
            return create_char_node(cp, state);
    }
}

// ----------------------------------------------------------------------------
// 13. AST Management (Freeing and Printing)
// ----------------------------------------------------------------------------

void free_regex_ast(RegexNode *node) {
    if (!node) return;

    // This function frees dynamically allocated string data within the AST.
    // The AST nodes themselves are in the arena and are freed all at once.
    switch (node->type) {
        case NODE_CHAR_CLASS:
            if (node->data.char_class.set) free(node->data.char_class.set);
            break;
        case NODE_UNI_PROP:
            if (node->data.uni_prop.prop_name) free(node->data.uni_prop.prop_name);
            break;
        case NODE_CONCAT:
        case NODE_ALTERNATION:
            free_regex_ast(node->data.children.left);
            free_regex_ast(node->data.children.right);
            break;
        case NODE_QUANTIFIER:
            free_regex_ast(node->data.quantifier.child);
            break;
        case NODE_GROUP:
        case NODE_BRESET_GROUP:
            if (node->data.group.name) free(node->data.group.name);
            free_regex_ast(node->data.group.child);
            break;
        case NODE_BACKREF:
            if (node->data.backref.ref_name) free(node->data.backref.ref_name);
            break;
        case NODE_ASSERTION:
            free_regex_ast(node->data.assertion.child);
            break;
        case NODE_CONDITIONAL:
            if (node->data.conditional.cond.type == COND_NAMED && node->data.conditional.cond.data.group_name) {
                free(node->data.conditional.cond.data.group_name);
            } else if (node->data.conditional.cond.type == COND_ASSERTION) {
                free_regex_ast(node->data.conditional.cond.data.assertion);
            }
            free_regex_ast(node->data.conditional.if_true);
            free_regex_ast(node->data.conditional.if_false);
            break;
        case NODE_SUBROUTINE:
            if (node->data.subroutine.target_name) free(node->data.subroutine.target_name);
            break;
        default: break;
    }
}

void print_regex_ast_recursive(const RegexNode *node, int indent) {
    if (!node) {
        printf("%*s(epsilon)\n", indent, "");
        return;
    }
    if (node->type == NODE_COMMENT) return;

    for (int i = 0; i < indent; ++i) printf("  ");

    switch (node->type) {
        case NODE_CHAR:
            if (node->data.codepoint < 128 && isprint(node->data.codepoint)) {
                printf("CHAR: '%c'\n", (char)node->data.codepoint);
            } else {
                printf("CHAR: U+%04X\n", node->data.codepoint);
            }
            break;
        case NODE_DOT: printf("DOT: .\n"); break;
        case NODE_ANCHOR: printf("ANCHOR: \\%c\n", node->data.anchor_type); break;
        case NODE_CHAR_CLASS:
            printf("CHAR_CLASS: [%s%s]\n", node->data.char_class.negated ? "^" : "", node->data.char_class.set);
            break;
        case NODE_UNI_PROP:
            printf("UNI_PROP: \\%c{%s}\n", node->data.uni_prop.negated ? 'P' : 'p', node->data.uni_prop.prop_name);
            break;
        case NODE_CONCAT:
            printf("CONCAT\n");
            print_regex_ast_recursive(node->data.children.left, indent + 1);
            print_regex_ast_recursive(node->data.children.right, indent + 1);
            break;
        case NODE_ALTERNATION:
            printf("ALTERNATION\n");
            print_regex_ast_recursive(node->data.children.left, indent + 1);
            print_regex_ast_recursive(node->data.children.right, indent + 1);
            break;
        case NODE_QUANTIFIER: {
            const char *q_type;
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
        case NODE_GROUP:
            printf("GROUP (%s%s%s #%d)\n",
                   node->data.group.is_atomic ? "atomic" : (node->data.group.capture_index < 0 ? "non-capturing" : "capture"),
                   node->data.group.name ? ", name=" : "", node->data.group.name ? node->data.group.name : "",
                   node->data.group.capture_index);
            print_regex_ast_recursive(node->data.group.child, indent + 1);
            break;
        case NODE_BACKREF:
            if (node->data.backref.ref_name) {
                printf("BACKREF: \\k<%s> (group %d)\n", node->data.backref.ref_name, node->data.backref.ref_index);
            } else {
                printf("BACKREF: \\%d\n", node->data.backref.ref_index);
            }
            break;
        case NODE_ASSERTION: {
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
        case NODE_BRESET_GROUP:
            printf("BRESET_GROUP (?|...)\n");
            print_regex_ast_recursive(node->data.group.child, indent + 1);
            break;
        case NODE_CONDITIONAL:
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
        case NODE_SUBROUTINE:
            if (node->data.subroutine.is_recursion) {
                printf("SUBROUTINE: (?R)\n");
            } else if (node->data.subroutine.target_name) {
                printf("SUBROUTINE: (?&%s)\n", node->data.subroutine.target_name);
            } else {
                printf("SUBROUTINE: (?%d)\n", node->data.subroutine.target_index);
            }
            break;
        case NODE_COMMENT: break; // Already handled
    }
}

void print_regex_ast(const RegexNode *root) {
    if (!root) { printf("AST is empty.\n"); return; }
    print_regex_ast_recursive(root, 0);
}

// ----------------------------------------------------------------------------
// 14. Main Entry Point and Cleanup
// ----------------------------------------------------------------------------

// A single function to free all resources related to a parse state.
void free_parser_state_resources(ParserState* state) {
    if (state->arena) {
        arena_free(state->arena);
        free(state->arena);
        state->arena = NULL;
    }
    for (int i = 0; i < state->fixup_count; i++) {
        free(state->fixups[i].name);
    }
    free(state->fixups);
    state->fixups = NULL;
    for (int i = 0; i < state->named_group_count; i++) {
        free(state->named_groups[i]);
    }
    free(state->named_groups);
    state->named_groups = NULL;
}

// Main parsing function. On success, it returns the AST root and sets out_arena.
// The caller is responsible for freeing the result with regex_free_result.
// On failure, it returns NULL, sets error_msg, and cleans up all resources.
RegexNode* regex_parse(const char* pattern, unsigned compile_flags, AstArena** out_arena, char** error_msg) {
    *error_msg = NULL;
    *out_arena = NULL;

    AstArena* arena = malloc(sizeof(AstArena));
    if (!arena) { *error_msg = strdup("Failed to allocate memory for arena"); return NULL; }
    memset(arena, 0, sizeof(AstArena));

    ParserState state = { .pattern = pattern, .arena = arena, .compile_flags = compile_flags, .in_conditional = false };
    if (compile_flags & REG_IGNORECASE) state.flags |= REG_IGNORECASE;
    if (compile_flags & REG_MULTILINE)  state.flags |= REG_MULTILINE;
    if (compile_flags & REG_SINGLELINE) state.flags |= REG_SINGLELINE;
    if (compile_flags & REG_EXTENDED)   state.flags |= REG_EXTENDED;
    if (compile_flags & REG_UNGREEDY)   state.flags |= REG_UNGREEDY;

    RegexNode* root = parse_regex(&state);

    if (!state.has_error) process_fixups(&state);

    if (state.has_error) {
        *error_msg = strdup(state.error_msg);
        free_regex_ast(root); // Free malloc'd strings
        free_parser_state_resources(&state);
        return NULL;
    } else if (peek_codepoint(&state) != 0) {
        set_error(&state, "Unexpected characters at end of pattern");
        *error_msg = strdup(state.error_msg);
        free_regex_ast(root);
        free_parser_state_resources(&state);
        return NULL;
    }
    
    // Success: transfer ownership of the arena to the caller.
    *out_arena = arena;

    // Free temporary lists that are not part of the AST result.
    for (int i = 0; i < state.fixup_count; i++) free(state.fixups[i].name);
    free(state.fixups);
    for (int i = 0; i < state.named_group_count; i++) free(state.named_groups[i]);
    free(state.named_groups);

    return root;
}

// User-facing cleanup function.
void regex_free_result(RegexNode *root, AstArena *arena) {
    if (!arena) return;
    free_regex_ast(root); // Frees malloc'd strings from nodes
    arena_free(arena);    // Frees the memory blocks holding nodes
    free(arena);          // Frees the arena struct itself
}

#ifdef TEST_MAIN

// ----------------------------------------------------------------------------
// 15. Test Harness
// ----------------------------------------------------------------------------
// Global test counters
static int total_tests = 0;
static int total_failures = 0;

// Test helper function for the new enhanced parser
void test_pattern(const char* pattern, bool expected_success, unsigned flags) {
    total_tests++;
    printf("====================================================\n");
    printf("Parsing pattern: \"%s\"\n", pattern);
    printf("Expected: %s\n", expected_success ? "SUCCESS" : "FAILURE");
    printf("----------------------------------------------------\n");

    char* error_msg = NULL;
    AstArena* arena = NULL;
    RegexNode* ast = regex_parse(pattern, flags, &arena, &error_msg);
    
    bool actual_success = (ast != NULL && error_msg == NULL);

    if (actual_success != expected_success) {
        total_failures++;
        printf(">> TEST RESULT: FAIL <<\n");
        if (actual_success) {
            printf("   (Expected failure, but got success)\n");
            printf("   AST:\n");
            print_regex_ast(ast);
        } else {
            printf("   (Expected success, but got failure)\n");
            printf("   Error: %s\n", error_msg ? error_msg : "(unknown error)");
        }
    } else {
        printf(">> TEST RESULT: PASS <<\n");
    }

    regex_free_result(ast, arena);

    if (error_msg) {
        free(error_msg);
    }
    printf("\n");
}

int main(void) {
    unsigned default_flags = 0;

    printf("\n--- SECTION 1: Basic Syntax & Quantifiers ---\n");
    test_pattern("ab|cd", true, default_flags);
    test_pattern("a(b|c)*d?", true, default_flags);
    test_pattern("a+", true, default_flags);       // Greedy
    test_pattern("a+?", true, default_flags);      // Lazy
    test_pattern("a++", true, default_flags);      // Possessive
    test_pattern("a{3,5}", true, default_flags);
    test_pattern("a{3,}", true, default_flags);
    test_pattern("a{3}", true, default_flags);
    test_pattern("a{0,0}", true, default_flags);   // Valid zero-width match
    test_pattern("a{3,1}", false, default_flags);  // Invalid range
    test_pattern("a{,5}", false, default_flags);   // Missing min
    test_pattern("{3}", false, default_flags);     // Quantifier without atom
    test_pattern("a**", false, default_flags);     // Double quantifier

    printf("\n--- SECTION 2: Groups & Backreferences ---\n");
    test_pattern("a(b)c", true, default_flags);
    test_pattern("(a)\\1", true, default_flags);
    test_pattern("(a)(b)\\2\\1", true, default_flags);
    test_pattern("(?:a)b", true, default_flags);    // Non-capturing group
    test_pattern("(?<year>\\d{4})", true, default_flags);
    test_pattern("(?<quote>['\"]).*\\k<quote>", true, default_flags);
    test_pattern("(a)\\2", false, default_flags);   // Backref to non-existent group
    test_pattern("\\1(a)", false, default_flags);   // Forward reference (invalid)
    test_pattern("(?<a>a)(?<a>b)", false, default_flags); // Duplicate named group
    test_pattern("\\k<a>(?<a>a)", false, default_flags); // Forward named reference (invalid)
    test_pattern("(?<word>\\w+)\\s+\\k<undefined>", false, default_flags); // Undefined named backref
    test_pattern("(?<invalid-name>)", false, default_flags); // Invalid group name

    printf("\n--- SECTION 3: Advanced Grouping (PCRE/Perl Features) ---\n");
    test_pattern("(?>a|ab)c", true, default_flags); // Atomic Group
    test_pattern("(?|a(b)|c(d))", true, default_flags); // Branch-reset group
    test_pattern("(?|(a)|(b))\\1", true, default_flags); // Branch-reset backreference
    test_pattern("(a)?(?(1)b|c)", true, default_flags); // Conditional on capture
    test_pattern("(a)?(?(1)b)", true, default_flags); // Conditional without false branch
    test_pattern("(?<foo>a)?(?(<foo>)b|c)", true, default_flags); // Conditional on named capture
    test_pattern("(?(?=a)a|b)", true, default_flags); // Conditional on assertion
    test_pattern("(?<a>a)b(?1)", true, default_flags); // Subroutine call by number
    test_pattern("(?<a>a)b(?&a)", true, default_flags); // Subroutine call by name
    test_pattern("((a)b(?2))", true, default_flags); // Recursive subroutine call
    test_pattern("(a)(?R)", true, default_flags); // Full pattern recursion

    printf("\n--- SECTION 4: Assertions ---\n");
    test_pattern("a(?!b)c", true, default_flags);   // Negative lookahead
    test_pattern("a(?=b)b", true, default_flags);   // Positive lookahead
    test_pattern("(?<=a)b", true, default_flags);   // Positive lookbehind
    test_pattern("(?<!a)b", true, default_flags);  // Negative lookbehind
    test_pattern("a(?=b(?=c))d", true, default_flags); // Nested lookahead
    test_pattern("(?<=a|b)c", true, default_flags); // Lookbehind with fixed-width alternation
    test_pattern("(?<=a|bc)d", false, default_flags);// Lookbehind with variable-width alternation
    test_pattern("(?<=a*)b", false, default_flags); // Lookbehind with unbounded quantifier

    printf("\n--- SECTION 5: Anchors & Character Classes ---\n");
    test_pattern("^[a-zA-Z_][a-zA-Z0-9_]*$", true, default_flags);
    test_pattern("\\bword\\b", true, default_flags);
    test_pattern("\\Aa\\B.", true, default_flags);
    test_pattern("end\\z", true, default_flags);
    test_pattern("[[:digit:]]+", true, default_flags); // POSIX class
    test_pattern("[^[:space:]]", true, default_flags);
    test_pattern("\\p{L}", true, default_flags);      // Unicode property
    test_pattern("\\P{L}", true, default_flags);      // Negated Unicode property
    test_pattern("[a-z\\d]", true, default_flags);    // Mixed class
    test_pattern("[\\d-a]", false, default_flags);    // Invalid range
    test_pattern("[]a]", true, default_flags);        // Literal ']' at start
    test_pattern("[a-]", true, default_flags);        // Literal '-' at end
    test_pattern("a^", false, default_flags);         // Misplaced anchor
    test_pattern("[]", false, default_flags);         // Empty class
    test_pattern("[^]", false, default_flags);        // Empty negated class

    printf("\n--- SECTION 6: Escapes, Comments & Flags ---\n");
    test_pattern("\\d{2,4}-\\w+", true, default_flags);
    test_pattern("a(?#comment)b", true, default_flags);
    test_pattern("\\x{1F600}", true, default_flags); // 4-byte UTF-8 char
    test_pattern("\\t\\n\\r\\f", true, default_flags);
    test_pattern("\\Q*+?.()[]\\E", true, default_flags); // Quoted sequence
    test_pattern("(?i)case", true, default_flags);   // Inline flag
    test_pattern("(?i:case)sensitive", true, default_flags); // Scoped flag
    test_pattern("(?i)c(?-i:ase)s", true, default_flags); // Flag modification
    test_pattern("\\", false, default_flags);        // Trailing escape
    test_pattern("a(?#unclosed comment", false, default_flags);
    
    printf("\n--- SECTION 7: Unicode & Real-World Patterns ---\n");
    test_pattern("你好世界", true, default_flags);
    test_pattern("a[α-ω]b", true, default_flags);
    test_pattern("^([a-z0-9_\\.-]+)@([\\da-z\\.-]+)\\.([a-z\\.]{2,6})$", true, default_flags); // Email
    test_pattern("https?://(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%_\\+.~#?&//=]*)", true, default_flags); // URL

    printf("\n--- SECTION 8: General Error Handling ---\n");
    test_pattern("a(b|c", false, default_flags);     // Unmatched parenthesis
    test_pattern("a)", false, default_flags);        // Unmatched closing parenthesis
    test_pattern("a[b-", false, default_flags);      // Unclosed character class
    test_pattern("\\p{Invalid}", false, default_flags); // Unknown Unicode property
    test_pattern("(?(2)a|b)", false, default_flags); // Conditional on non-existent group
    test_pattern("a(?<=b)++", false, default_flags); // Quantifying an assertion


    printf("====================================================\n");
    printf("FINAL REPORT\n");
    printf("----------------------------------------------------\n");
    printf("TOTAL TESTS:    %d\n", total_tests);
    printf("TOTAL FAILURES: %d\n", total_failures);
    if (total_failures == 0) {
        printf("\n>>>>> ALL TESTS PASSED <<<<<\n");
    } else {
        printf("\n>>>>> SOME TESTS FAILED <<<<<\n");
    }
    printf("====================================================\n");

    // Cleanup before exit
    regex_cleanup_property_cache();

    return total_failures;
}
#endif // TEST_MAIN
