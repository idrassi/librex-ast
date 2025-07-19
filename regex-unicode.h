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

#ifndef REGEX_UNICODE_H
#define REGEX_UNICODE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "regex-internals.h"

// Number of 32‑bit words needed to cover U+0000–U+10FFFF
#define UNI_BM_WORDS  (0x110000/32)

// Unicode category mappings
typedef struct {
    uint32_t start;
    uint32_t end;
    const char* category;
} UnicodeRange;

// UTF-8 decoding function
bool utf8_codepoint(const uint8_t *s, size_t len, size_t *i, uint32_t *cp);

// Unicode property bitmap functions
uint32_t* build_unicode_property_bitmap(const char* prop_name, AstArena* arena);
uint32_t* build_class_bitmap(const char *spec, AstArena *arena);

// Helper functions
void set_bit_in_bitmap(uint32_t* bitmap, uint32_t codepoint);
bool property_matches(const char* prop_name, const char* target);

#endif // REGEX_UNICODE_H