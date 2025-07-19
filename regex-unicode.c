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

#include "regex-unicode.h"
#include "regex-parser.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif

// External function from arena allocator
void *arena_alloc(AstArena *arena, size_t size);

// Sample Unicode ranges for major categories
static const UnicodeRange unicode_ranges[] = {
    // Basic Latin uppercase letters
    {0x0041, 0x005A, "Lu"},
    {0x0041, 0x005A, "L"},
    
    // Basic Latin lowercase letters
    {0x0061, 0x007A, "Ll"},
    {0x0061, 0x007A, "L"},

    // ASCII control characters (complete set)
    {0x0000, 0x001F, "Cc"},  // C0 controls
    {0x0000, 0x001F, "C"},
    {0x007F, 0x007F, "Cc"},  // DEL
    {0x007F, 0x007F, "C"},
    
    // Whitespace characters (separate from control)
    {0x0009, 0x0009, "Cc"},  // tab (control)
    {0x0009, 0x0009, "C"},
    {0x000A, 0x000D, "Cc"},  // LF, VT, FF, CR (control)
    {0x000A, 0x000D, "C"},
    {0x0020, 0x0020, "Zs"},  // space (separator)
    {0x0020, 0x0020, "Z"},
    
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
    
    // Missing: Other decimal digits
    {0x0660, 0x0669, "Nd"},  // Arabic-Indic digits
    {0x0660, 0x0669, "N"},
    {0x06F0, 0x06F9, "Nd"},  // Extended Arabic-Indic digits
    {0x06F0, 0x06F9, "N"},
    {0x07C0, 0x07C9, "Nd"},  // NKo digits
    {0x07C0, 0x07C9, "N"},
    {0x0966, 0x096F, "Nd"},  // Devanagari digits
    {0x0966, 0x096F, "N"},
    {0x09E6, 0x09EF, "Nd"},  // Bengali digits
    {0x09E6, 0x09EF, "N"},
    {0x0A66, 0x0A6F, "Nd"},  // Gurmukhi digits
    {0x0A66, 0x0A6F, "N"},
    {0x0AE6, 0x0AEF, "Nd"},  // Gujarati digits
    {0x0AE6, 0x0AEF, "N"},
    {0x0B66, 0x0B6F, "Nd"},  // Oriya digits
    {0x0B66, 0x0B6F, "N"},
    {0x0BE6, 0x0BEF, "Nd"},  // Tamil digits
    {0x0BE6, 0x0BEF, "N"},
    {0x0C66, 0x0C6F, "Nd"},  // Telugu digits
    {0x0C66, 0x0C6F, "N"},
    {0x0CE6, 0x0CEF, "Nd"},  // Kannada digits
    {0x0CE6, 0x0CEF, "N"},
    {0x0D66, 0x0D6F, "Nd"},  // Malayalam digits
    {0x0D66, 0x0D6F, "N"},
    {0x0DE6, 0x0DEF, "Nd"},  // Sinhala digits
    {0x0DE6, 0x0DEF, "N"},
    {0x0E50, 0x0E59, "Nd"},  // Thai digits
    {0x0E50, 0x0E59, "N"},
    {0x0ED0, 0x0ED9, "Nd"},  // Lao digits
    {0x0ED0, 0x0ED9, "N"},
    {0x0F20, 0x0F29, "Nd"},  // Tibetan digits
    {0x0F20, 0x0F29, "N"},
    {0x1040, 0x1049, "Nd"},  // Myanmar digits
    {0x1040, 0x1049, "N"},
    {0x1090, 0x1099, "Nd"},  // Myanmar Shan digits
    {0x1090, 0x1099, "N"},
    {0x17E0, 0x17E9, "Nd"},  // Khmer digits
    {0x17E0, 0x17E9, "N"},
    {0x1810, 0x1819, "Nd"},  // Mongolian digits
    {0x1810, 0x1819, "N"},
    {0x1946, 0x194F, "Nd"},  // Limbu digits
    {0x1946, 0x194F, "N"},
    {0x19D0, 0x19D9, "Nd"},  // New Tai Lue digits
    {0x19D0, 0x19D9, "N"},
    {0x1A80, 0x1A89, "Nd"},  // Tai Tham Hora digits
    {0x1A80, 0x1A89, "N"},
    {0x1A90, 0x1A99, "Nd"},  // Tai Tham Tham digits
    {0x1A90, 0x1A99, "N"},
    {0x1B50, 0x1B59, "Nd"},  // Balinese digits
    {0x1B50, 0x1B59, "N"},
    {0x1BB0, 0x1BB9, "Nd"},  // Sundanese digits
    {0x1BB0, 0x1BB9, "N"},
    {0x1C40, 0x1C49, "Nd"},  // Lepcha digits
    {0x1C40, 0x1C49, "N"},
    {0x1C50, 0x1C59, "Nd"},  // Ol Chiki digits
    {0x1C50, 0x1C59, "N"},
    {0xA620, 0xA629, "Nd"},  // Vai digits
    {0xA620, 0xA629, "N"},
    {0xA8D0, 0xA8D9, "Nd"},  // Saurashtra digits
    {0xA8D0, 0xA8D9, "N"},
    {0xA900, 0xA909, "Nd"},  // Kayah Li digits
    {0xA900, 0xA909, "N"},
    {0xA9D0, 0xA9D9, "Nd"},  // Javanese digits
    {0xA9D0, 0xA9D9, "N"},
    {0xA9F0, 0xA9F9, "Nd"},  // Myanmar Tai Laing digits
    {0xA9F0, 0xA9F9, "N"},
    {0xAA50, 0xAA59, "Nd"},  // Cham digits
    {0xAA50, 0xAA59, "N"},
    {0xABF0, 0xABF9, "Nd"},  // Meetei Mayek digits
    {0xABF0, 0xABF9, "N"},
    {0xFF10, 0xFF19, "Nd"},  // Fullwidth digits
    {0xFF10, 0xFF19, "N"},
    
    // Enhanced ASCII punctuation (split into subcategories)
    {0x0021, 0x0023, "Po"},  // ! " #
    {0x0021, 0x0023, "P"},
    {0x0025, 0x0027, "Po"},  // % & '
    {0x0025, 0x0027, "P"},
    {0x002A, 0x002A, "Po"},  // *
    {0x002A, 0x002A, "P"},
    {0x002C, 0x002C, "Po"},  // ,
    {0x002C, 0x002C, "P"},
    {0x002E, 0x002F, "Po"},  // . /
    {0x002E, 0x002F, "P"},
    {0x003A, 0x003B, "Po"},  // : ;
    {0x003A, 0x003B, "P"},
    {0x003F, 0x0040, "Po"},  // ? @
    {0x003F, 0x0040, "P"},
    {0x005C, 0x005C, "Po"},  // backslash
    {0x005C, 0x005C, "P"},
    {0x00A1, 0x00A1, "Po"},  // inverted exclamation
    {0x00A1, 0x00A1, "P"},
    {0x00A7, 0x00A7, "Po"},  // section sign
    {0x00A7, 0x00A7, "P"},
    {0x00B6, 0x00B7, "Po"},  // pilcrow, middle dot
    {0x00B6, 0x00B7, "P"},
    {0x00BF, 0x00BF, "Po"},  // inverted question mark
    {0x00BF, 0x00BF, "P"},
    
    // Punctuation subcategories (parentheses, brackets, etc.)
    {0x0028, 0x0028, "Ps"},  // (
    {0x0028, 0x0028, "P"},
    {0x0029, 0x0029, "Pe"},  // )
    {0x0029, 0x0029, "P"},
    {0x005B, 0x005B, "Ps"},  // [
    {0x005B, 0x005B, "P"},
    {0x005D, 0x005D, "Pe"},  // ]
    {0x005D, 0x005D, "P"},
    {0x007B, 0x007B, "Ps"},  // {
    {0x007B, 0x007B, "P"},
    {0x007D, 0x007D, "Pe"},  // }
    {0x007D, 0x007D, "P"},
    {0x0024, 0x0024, "Sc"},  // $ (currency)
    {0x0024, 0x0024, "S"},
    {0x002B, 0x002B, "Sm"},  // + (math)
    {0x002B, 0x002B, "S"},
    {0x003C, 0x003E, "Sm"},  // < = > (math)
    {0x003C, 0x003E, "S"},
    {0x005E, 0x005E, "Sk"},  // ^ (modifier)
    {0x005E, 0x005E, "S"},
    {0x0060, 0x0060, "Sk"},  // ` (modifier)
    {0x0060, 0x0060, "S"},
    {0x007C, 0x007C, "Sm"},  // | (math)
    {0x007C, 0x007C, "S"},
    {0x007E, 0x007E, "Sm"},  // ~ (math)
    {0x007E, 0x007E, "S"},
    
    // Enhanced whitespace
    {0x0009, 0x000D, "Cc"},  // tab, LF, VT, FF, CR
    {0x0009, 0x000D, "C"},
    {0x0020, 0x0020, "Zs"},  // space
    {0x0020, 0x0020, "Z"},
    {0x00A0, 0x00A0, "Zs"},  // non-breaking space
    {0x00A0, 0x00A0, "Z"},
    {0x1680, 0x1680, "Zs"},  // Ogham space mark
    {0x1680, 0x1680, "Z"},
    {0x2000, 0x200A, "Zs"},  // En quad through hair space
    {0x2000, 0x200A, "Z"},
    {0x2028, 0x2028, "Zl"},  // Line separator
    {0x2028, 0x2028, "Z"},
    {0x2029, 0x2029, "Zp"},  // Paragraph separator
    {0x2029, 0x2029, "Z"},
    {0x202F, 0x202F, "Zs"},  // Narrow no-break space
    {0x202F, 0x202F, "Z"},
    {0x205F, 0x205F, "Zs"},  // Medium mathematical space
    {0x205F, 0x205F, "Z"},
    {0x3000, 0x3000, "Zs"},  // Ideographic space
    {0x3000, 0x3000, "Z"},
    
    // Common CJK ranges
    {0x4E00, 0x9FFF, "Lo"},  // CJK Unified Ideographs (mostly)
    {0x4E00, 0x9FFF, "L"},
    {0x3400, 0x4DBF, "Lo"},  // CJK Extension A
    {0x3400, 0x4DBF, "L"},
    {0x3040, 0x309F, "Lo"},  // Hiragana
    {0x3040, 0x309F, "L"},
    {0x30A0, 0x30FF, "Lo"},  // Katakana
    {0x30A0, 0x30FF, "L"},
    {0xAC00, 0xD7AF, "Lo"},  // Hangul Syllables
    {0xAC00, 0xD7AF, "L"},
    
    // Arabic (entire block)
    {0x0600, 0x06FF, "L"},   // Letters
    {0x0600, 0x06FF, "M"},   // Marks
    {0x0600, 0x06FF, "N"},   // Numbers
    {0x0600, 0x06FF, "P"},   // Punctuation
    {0x0750, 0x077F, "L"},   // Arabic Supplement
    {0x08A0, 0x08FF, "L"},   // Arabic Extended-A
    {0x08A0, 0x08FF, "M"},
    
    // Hebrew (entire block)
    {0x0590, 0x05FF, "L"},   // Letters
    {0x0590, 0x05FF, "M"},   // Marks
    {0x0590, 0x05FF, "P"},   // Punctuation
    
    // Devanagari (entire block)
    {0x0900, 0x097F, "L"},   // Letters
    {0x0900, 0x097F, "M"},   // Marks
    {0x0900, 0x097F, "N"},   // Numbers
    {0x0900, 0x097F, "P"},   // Punctuation
    
    // Latin Extended-A
    {0x0100, 0x017F, "L"},   // Mixed case, simplified
    
    // Greek and Coptic (full block)
    {0x0370, 0x03FF, "L"},
    {0x0370, 0x03FF, "M"},
    {0x0370, 0x03FF, "N"},
    {0x0370, 0x03FF, "S"},
    
    // Cyrillic (full block)
    {0x0400, 0x04FF, "L"},
    {0x0400, 0x04FF, "M"},
    {0x0400, 0x04FF, "N"},
    
    // End marker
    {0, 0, NULL}
};

bool utf8_codepoint(const uint8_t *s, size_t len, size_t *i, uint32_t *cp) {
    if (*i >= len) return false;
    uint32_t c = 0;
    unsigned char c0 = s[*i];
    int todo = 0;
    if (!(c0 & 0x80)) {
        *cp = c0;
        (*i)++;
        return true;
    }
    if ((c0 & 0xe0) == 0xc0) { c = c0 & 0x1f; todo = 1; }
    else if ((c0 & 0xf0) == 0xe0) { c = c0 & 0x0f; todo = 2; }
    else if ((c0 & 0xf8) == 0xf0) { c = c0 & 0x07; todo = 3; }
    else return false;
    if (*i + todo >= len) return false;
    for (int k = 1; k <= todo; ++k) {
        unsigned char ck = s[*i + k];
        if ((ck & 0xc0) != 0x80) return false;
        c = (c << 6) | (ck & 0x3f);
    }
    *cp = c;
    *i += 1 + todo;
    return true;
}

void set_bit_in_bitmap(uint32_t* bitmap, uint32_t codepoint) {
    if (codepoint >= 0x110000) return;
    bitmap[codepoint / 32] |= (1U << (codepoint % 32));
}

// Check if a property name matches (handles both full names and abbreviations)
bool property_matches(const char* prop_name, const char* target) {
    if (!prop_name || !target) return false;
    
    // Handle major categories specified by a single letter
    if (strlen(prop_name) == 1 && tolower(prop_name[0]) == tolower(target[0])) {
        return true;
    }

    // Handle full property names
    if (strcasecmp(prop_name, target) == 0) {
        return true;
    }
    
    // Handle common aliases
    if (strcmp(prop_name, "alpha") == 0 && tolower(target[0]) == 'l') return true;
    if (strcmp(prop_name, "alnum") == 0 && (tolower(target[0]) == 'l' || tolower(target[0]) == 'n')) return true;
    if (strcmp(prop_name, "punct") == 0 && tolower(target[0]) == 'p') return true;
    if (strcmp(prop_name, "digit") == 0 && strcasecmp(target, "nd") == 0) return true;
    if (strcmp(prop_name, "space") == 0 && (tolower(target[0]) == 'z' || strcasecmp(target, "cc") == 0)) return true;
    if (strcmp(prop_name, "upper") == 0 && strcasecmp(target, "lu") == 0) return true;
    if (strcmp(prop_name, "lower") == 0 && strcasecmp(target, "ll") == 0) return true;
    
    return false;
}

// Build a bitmap for a specific Unicode property
uint32_t* build_unicode_property_bitmap(const char* prop_name, AstArena* arena) {
    uint32_t* bitmap = arena_alloc(arena, UNI_BM_WORDS * sizeof(uint32_t));
    if (!bitmap) return NULL;
    memset(bitmap, 0, UNI_BM_WORDS * sizeof(uint32_t));
    
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

// Unified character class bitmap builder
uint32_t* build_class_bitmap(const char *spec, AstArena *arena) {
    uint32_t *bm = arena_alloc(arena, UNI_BM_WORDS * sizeof(uint32_t));
    if (!bm) return NULL;
    memset(bm, 0, UNI_BM_WORDS * sizeof(uint32_t));

    #define SET_CP(cp) if(cp < 0x110000) (bm[cp>>5] |= (1u << (cp & 31)))
    #define MERGE_BITMAP(other_bm) \
        if (other_bm) { for (size_t w = 0; w < UNI_BM_WORDS; ++w) bm[w] |= other_bm[w]; }

    size_t spec_len = strlen(spec);
    size_t i = 0;
    
    while (i < spec_len) {
        // Handle POSIX character classes
        if (spec[i] == '[' && i + 1 < spec_len && spec[i+1] == ':') {
            size_t j = i + 2;
            while (j < spec_len && !(spec[j] == ':' && j + 1 < spec_len && spec[j+1] == ']')) j++;
            if (j >= spec_len) {
                i++; // treat as literal '['
                continue;
            }

            // Extract the class name
            size_t name_len = j - (i + 2);
            if (name_len < 20) {
                char name[20] = {0};
                for (size_t k = 0; k < name_len; ++k) {
                    name[k] = (char)tolower((unsigned char)spec[i + 2 + k]);
                }

                uint32_t* posix_bm = NULL;
                if (strcmp(name, "space") == 0) posix_bm = build_unicode_property_bitmap("space", arena);
                else if (strcmp(name, "digit") == 0) posix_bm = build_unicode_property_bitmap("nd", arena);
                else if (strcmp(name, "xdigit") == 0) {
                    posix_bm = arena_alloc(arena, UNI_BM_WORDS * sizeof(uint32_t));
                    if (posix_bm) {
                        memset(posix_bm, 0, UNI_BM_WORDS * sizeof(uint32_t));
                        for (uint32_t v = '0'; v <= '9'; ++v) set_bit_in_bitmap(posix_bm, v);
                        for (uint32_t v = 'A'; v <= 'F'; ++v) set_bit_in_bitmap(posix_bm, v);
                        for (uint32_t v = 'a'; v <= 'f'; ++v) set_bit_in_bitmap(posix_bm, v);
                    }
                }
                else if (strcmp(name, "lower") == 0) posix_bm = build_unicode_property_bitmap("ll", arena);
                else if (strcmp(name, "upper") == 0) posix_bm = build_unicode_property_bitmap("lu", arena);
                else if (strcmp(name, "alpha") == 0) posix_bm = build_unicode_property_bitmap("l", arena);
                else if (strcmp(name, "alnum") == 0) posix_bm = build_unicode_property_bitmap("alnum", arena);
                else if (strcmp(name, "blank") == 0) {
                    posix_bm = arena_alloc(arena, UNI_BM_WORDS * sizeof(uint32_t));
                    if (posix_bm) {
                        memset(posix_bm, 0, UNI_BM_WORDS * sizeof(uint32_t));
                        set_bit_in_bitmap(posix_bm, ' ');
                        set_bit_in_bitmap(posix_bm, '\t');
                    }
                }
                else if (strcmp(name, "punct") == 0) posix_bm = build_unicode_property_bitmap("p", arena);
                else if (strcmp(name, "cntrl") == 0) {
                    posix_bm = arena_alloc(arena, UNI_BM_WORDS * sizeof(uint32_t));
                    if (posix_bm) {
                        memset(posix_bm, 0, UNI_BM_WORDS * sizeof(uint32_t));
                        for (uint32_t v = 0; v < 0x20; ++v) set_bit_in_bitmap(posix_bm, v);
                        set_bit_in_bitmap(posix_bm, 0x7F);
                    }
                }

                MERGE_BITMAP(posix_bm);
            }
            i = j + 2; // skip over ":]"
            continue;
        }

        uint32_t cp1;
        size_t current_pos = i;
        
        // Handle escaped constructs
        if (spec[i] == '\\' && i + 1 < spec_len) {
            i++; // consume '\'
            char e = spec[i++];
            uint32_t* shorthand_bm = NULL;
            switch (e) {
                case 'd': shorthand_bm = build_unicode_property_bitmap("nd", arena); break;
                case 'D': 
                    shorthand_bm = build_unicode_property_bitmap("nd", arena);
                    if (shorthand_bm) {
                        for (size_t w = 0; w < UNI_BM_WORDS; ++w) shorthand_bm[w] = ~shorthand_bm[w];
                    }
                    break;
                case 'w': shorthand_bm = build_unicode_property_bitmap("word", arena); break;
                case 'W':
                    shorthand_bm = build_unicode_property_bitmap("word", arena);
                    if (shorthand_bm) {
                        for (size_t w = 0; w < UNI_BM_WORDS; ++w) shorthand_bm[w] = ~shorthand_bm[w];
                    }
                    break;
                case 's': shorthand_bm = build_unicode_property_bitmap("space", arena); break;
                case 'S':
                    shorthand_bm = build_unicode_property_bitmap("space", arena);
                    if (shorthand_bm) {
                        for (size_t w = 0; w < UNI_BM_WORDS; ++w) shorthand_bm[w] = ~shorthand_bm[w];
                    }
                    break;
                default:
                    SET_CP((uint32_t)e);
                    continue;
            }
            MERGE_BITMAP(shorthand_bm);
            continue;
        }

        // Handle literal characters and ranges
        if (!utf8_codepoint((const uint8_t*)spec, spec_len, &i, &cp1)) {
            // Invalid UTF-8, treat as raw byte
            cp1 = (unsigned char)spec[current_pos];
            i = current_pos + 1;
        }

        // Check for range operator a-z
        if (i < spec_len && spec[i] == '-' && i + 1 < spec_len) {
            i++; // consume '-'
            uint32_t cp2;
            size_t next_pos = i;
            if (utf8_codepoint((const uint8_t*)spec, spec_len, &i, &cp2)) {
                uint32_t lo = cp1 < cp2 ? cp1 : cp2;
                uint32_t hi = cp1 < cp2 ? cp2 : cp1;
                for (uint32_t x = lo; x <= hi; ++x) SET_CP(x);
                continue;
            }
            // Not a valid range, treat '-' as a literal
            i = next_pos;
            SET_CP(cp1);
            SET_CP('-');
            continue;
        }
        
        // Single literal codepoint
        SET_CP(cp1);
    }

    #undef SET_CP
    #undef MERGE_BITMAP
    return bm;
}