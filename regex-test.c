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
#include <windows.h>
#endif
#include "regex-parser.h"
#include <stdio.h>
#include <stdlib.h>
// ----------------------------------------------------------------------------
// Test Harness
// ----------------------------------------------------------------------------

// Global test counters
static int total_tests = 0;
static int total_failures = 0;

// Define a struct for expected capture groups
typedef struct {
    int start;
    int end;
} ExpectedCapture;

// Test helper for matching
void test_match_pattern(const char* pattern, uint32_t flags, const char* subject,
                        bool expected_match, int expected_start, int expected_end,
                        ExpectedCapture* expected_captures, int expected_capture_count) {
    total_tests++;

    regex_err error = {0};
    regex_compiled* rx = regex_compile(pattern, flags, &error);
    if (!rx || error.code != REGEX_OK) {
        total_failures++;
        printf("====================================================\n");
        printf("Matching pattern: \"%s\" against \"%s\"\n", pattern, subject);
        printf("Flags: 0x%X\n", flags);
        printf("Expected: %s [%d-%d] with %d captures\n",
            expected_match ? "MATCH" : "NO MATCH", expected_start, expected_end, expected_capture_count);
        printf("----------------------------------------------------\n");
        printf(">> TEST RESULT: FAIL << (Compilation failed: %s)\n", error.msg ? error.msg : "(unknown)");
        return;
    }

    regex_match_result result = {0};
    size_t subject_len = strlen(subject);
    int match_count = regex_match(rx, subject, subject_len, &result);

    bool actual_match = (match_count > 0);
    bool success = true;

    if (actual_match != expected_match) {
        success = false;
    } else if (actual_match) {
        if (result.match_start != expected_start || result.match_end != expected_end) {
            success = false;
        }
        if (result.capture_count != expected_capture_count) {
            success = false;
        } else if (expected_captures) {
            for (int i = 0; i < expected_capture_count; i++) {
                if (result.capture_starts[i] != expected_captures[i].start ||
                    result.capture_ends[i] != expected_captures[i].end) {
                    success = false;
                    break;
                }
            }
        }
    }

    if (!success) {
        total_failures++;
        printf("====================================================\n");
        printf("Matching pattern: \"%s\" against \"%s\"\n", pattern, subject);
        printf("Flags: 0x%X\n", flags);
        printf("Expected: %s [%d-%d] with %d captures\n",
            expected_match ? "MATCH" : "NO MATCH", expected_start, expected_end, expected_capture_count);
        printf("----------------------------------------------------\n");
        printf(">> TEST RESULT: FAIL <<\n");
        if (actual_match) {
            printf("   Actual: MATCH [%d-%d] with %d captures\n",
                   result.match_start, result.match_end, result.capture_count);
            for (int i = 0; i < result.capture_count; i++) {
                printf("     Group %d: [%d-%d]\n", i + 1, result.capture_starts[i], result.capture_ends[i]);
            }
        } else {
            printf("   Actual: NO MATCH\n");
        }
        // printf("\n");
    } else {
        //printf(">> TEST RESULT: PASS <<\n");
        //printf("\n");
    }

    // Cleanup
    regex_free_match_result(&result, NULL);
    regex_free(rx);
}

// Test helper function for the parser
void test_pattern(const char* pattern, bool expected_success, unsigned flags) {
    total_tests++;

    regex_err error = {0};
    regex_compiled* rx = regex_compile(pattern, flags, &error);

    bool actual_success = (rx != NULL && error.code == REGEX_OK);

    if (actual_success != expected_success) {
        total_failures++;
        printf("====================================================\n");
        printf("Parsing pattern: \"%s\"\n", pattern);
        printf("Expected: %s\n", expected_success ? "SUCCESS" : "FAILURE");
        printf("----------------------------------------------------\n");
        printf(">> TEST RESULT: FAIL <<\n");
        if (actual_success) {
            printf("   (Expected failure, but got success)\n");
            printf("   AST:\n");
            print_regex_ast(rx);
        } else {
            printf("   (Expected success, but got failure)\n");
            printf("   Error: ");
            if (error.code != REGEX_OK) {
                printf("Error at line %d, column %d: %s\n", error.line, error.col, error.msg ? error.msg : "(unknown error)");
            } else {
                printf("(unknown error)\n");
            }
        }
        //printf("\n");
    } else {
        //printf(">> TEST RESULT: PASS <<\n");
        // printf("\n");
    }

    if (rx) {
        regex_free(rx);
    }


}

int main(void) {
    unsigned default_flags = 0;
#ifdef _WIN32
    // set console output to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
#endif

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
    test_pattern("a{,5}", true, default_flags);   
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
    test_pattern("\\1(a)", true, default_flags);   // Forward reference 
    test_pattern("(?<a>a)(?<a>b)", false, default_flags); // Duplicate named group
    test_pattern("\\k<a>(?<a>a)", true, default_flags); // Forward named reference
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
    test_pattern("(?<=a|bc)d", true, default_flags);// Lookbehind with variable-width alternation
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
    test_pattern("a^", true, default_flags);
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
    test_pattern("a(?<=b)++", true, default_flags); // Quantifying an assertion

    printf("\n--- SECTION 9: Basic Matching Tests ---\n");
    test_match_pattern("ab|cd", 0, "ab", true, 0, 2, NULL, 0);
    test_match_pattern("ab|cd", 0, "cd", true, 0, 2, NULL, 0);
    test_match_pattern("ab|cd", 0, "ac", false, -1, -1, NULL, 0);
    test_match_pattern("a(b|c)*d?", 0, "abd", true, 0, 3, (ExpectedCapture[]) { { 1, 2 } }, 1);
    test_match_pattern("a(b|c)*d?", 0, "accccd", true, 0, 6, (ExpectedCapture[]) { { 4, 5 } }, 1); // Last capture overwrites
    test_match_pattern("a+", 0, "aaa", true, 0, 3, NULL, 0);
    test_match_pattern("a+?", 0, "aaa", true, 0, 1, NULL, 0); // Lazy matches minimal
    test_match_pattern("a++", 0, "aaa", true, 0, 3, NULL, 0); // Possessive
    test_match_pattern("a{3,5}", 0, "aaaa", true, 0, 4, NULL, 0);
    test_match_pattern("a{3,}", 0, "aa", false, -1, -1, NULL, 0);
    test_match_pattern("a{3}", 0, "aaa", true, 0, 3, NULL, 0);
    test_match_pattern("a{0,0}", 0, "b", true, 0, 0, NULL, 0); // Zero-width match at start

    printf("\n--- SECTION 10: Groups & Backreferences Matching ---\n");
    test_match_pattern("a(b)c", 0, "abc", true, 0, 3, (ExpectedCapture[]) { { 1, 2 } }, 1);
    test_match_pattern("(a)\\1", 0, "aa", true, 0, 2, (ExpectedCapture[]) { { 0, 1 } }, 1);
    test_match_pattern("(a)(b)\\2\\1", 0, "abba", true, 0, 4, (ExpectedCapture[]) { { 0, 1 }, { 1,2 } }, 2);
    test_match_pattern("(?:a)b", 0, "ab", true, 0, 2, NULL, 0); // Non-capturing
    test_match_pattern("(?<year>\\d{4})", 0, "2023", true, 0, 4, (ExpectedCapture[]) { { 0, 4 } }, 1);
    test_match_pattern("(?<quote>['\"]).*\\k<quote>", 0, "'hello'", true, 0, 7, (ExpectedCapture[]) { { 0, 1 } }, 1);
    test_match_pattern("(?<quote>['\"]).*\\k<quote>", 0, "'hello\"", false, -1, -1, NULL, 0); // Mismatch quotes

    printf("\n--- SECTION 11: Advanced Grouping Matching ---\n");
    test_match_pattern("(?>a|ab)c", 0, "abc", false, -1, -1, NULL, 0);
    test_match_pattern("(?>a|ab)c", 0, "ac", true, 0, 2, NULL, 0);
    test_match_pattern("(?|a(b)|c(d))", 0, "ab", true, 0, 2, (ExpectedCapture[]) { { 1, 2 } }, 1);
    test_match_pattern("(?|a(b)|c(d))", 0, "cd", true, 0, 2, (ExpectedCapture[]) { { 1, 2 } }, 1); // Shared capture index
    test_match_pattern("(a)?(?(1)b|c)", 0, "ab", true, 0, 2, (ExpectedCapture[]) { { 0, 1 } }, 1);
    test_match_pattern("(a)?(?(1)b|c)", 0, "c", true, 0, 1, NULL, 0);
    test_match_pattern("(?<foo>a)?(?(<foo>)b|c)", 0, "ab", true, 0, 2, (ExpectedCapture[]) { { 0, 1 } }, 1);
    test_match_pattern("(?(?=a)a|b)", 0, "a", true, 0, 1, NULL, 0);
    test_match_pattern("(?(?=a)a|b)", 0, "b", true, 0, 1, NULL, 0);
    test_match_pattern("(?<a>a)b(?1)", 0, "abab", true, 0, 3, (ExpectedCapture[]) { { 0, 1 } }, 1); // Subroutine call
    test_match_pattern("(?<a>a)b(?&a)", 0, "aba", true, 0, 3, (ExpectedCapture[]) { { 0, 1 } }, 1);
    test_match_pattern("((a)b(?2))", 0, "abab", true, 0, 3, (ExpectedCapture[]) { { 0, 3 }, { 0,1 } }, 2);
    test_match_pattern("(a)(?R)", 0, "aa", false, -1, -1, NULL, 0);

    printf("\n--- SECTION 12: Assertions Matching ---\n");
    test_match_pattern("a(?!b)c", 0, "acc", true, 0, 2, NULL, 0);
    test_match_pattern("a(?!b)c", 0, "abc", false, -1, -1, NULL, 0);
    test_match_pattern("a(?=b)b", 0, "abb", true, 0, 2, NULL, 0);
    test_match_pattern("a(?=b)b", 0, "abc", true, 0, 2, NULL, 0);
    test_match_pattern("(?<=a)b", 0, "ab", true, 1, 2, NULL, 0);
    test_match_pattern("(?<=a)b", 0, "cb", false, -1, -1, NULL, 0);
    test_match_pattern("(?<!a)b", 0, "cb", true, 1, 2, NULL, 0);
    test_match_pattern("(?<!a)b", 0, "ab", false, -1, -1, NULL, 0);
    test_match_pattern("a(?=b(?=c)d)", 0, "abcd", false, -1, -1, NULL, 0);
    test_match_pattern("(?<=a|b)c", 0, "ac", true, 1, 2, NULL, 0);
    test_match_pattern("(?<=a|b)c", 0, "bc", true, 1, 2, NULL, 0);

    printf("\n--- SECTION 13: Anchors & Character Classes Matching ---\n");
    test_match_pattern("^[a-zA-Z_][a-zA-Z0-9_]*$", 0, "var_123", true, 0, 7, NULL, 0);
    test_match_pattern("^[a-zA-Z_][a-zA-Z0-9_]*$", 0, "123var", false, -1, -1, NULL, 0);
    test_match_pattern("\\bword\\b", 0, "word", true, 0, 4, NULL, 0);
    test_match_pattern("\\bword\\b", 0, "sword", false, -1, -1, NULL, 0);
    test_match_pattern("\\Aa\\B.", 0, "ab", true, 0, 2, NULL, 0);
    test_match_pattern("\\Aa\\B.", 0, "a b", false, -1, -1, NULL, 0); // \B requires non-word boundary
    test_match_pattern("end\\z", 0, "end", true, 0, 3, NULL, 0);
    test_match_pattern("end\\z", 0, "ends", false, -1, -1, NULL, 0);
    test_match_pattern("[[:digit:]]+", 0, "123", true, 0, 3, NULL, 0);
    test_match_pattern("[^[:space:]]", 0, "a", true, 0, 1, NULL, 0);
    test_match_pattern("[^[:space:]]", 0, " ", false, -1, -1, NULL, 0);
    test_match_pattern("\\p{L}", 0, "a", true, 0, 1, NULL, 0);
    test_match_pattern("\\p{L}", 0, "1", false, -1, -1, NULL, 0);
    test_match_pattern("\\P{L}", 0, "1", true, 0, 1, NULL, 0);
    test_match_pattern("[a-z\\d]", 0, "5", true, 0, 1, NULL, 0);
    test_match_pattern("[]a]", 0, "a", true, 0, 1, NULL, 0);
    test_match_pattern("[]a]", 0, "]", true, 0, 1, NULL, 0);
    test_match_pattern("[a-]", 0, "-", true, 0, 1, NULL, 0);

    printf("\n--- SECTION 14: Escapes, Comments & Flags Matching ---\n");
    test_match_pattern("\\d{2,4}-\\w+", 0, "1234-abc", true, 0, 8, NULL, 0);
    test_match_pattern("a(?#comment)b", 0, "ab", true, 0, 2, NULL, 0);
    test_match_pattern("\\x{1F600}", 0, "😀", true, 0, 4, NULL, 0); // Assuming UTF-8 handling
    test_match_pattern("\\t\\n\\r\\f", 0, "\t\n\r\f", true, 0, 4, NULL, 0);
    test_match_pattern("\\Q*+?.()[]\\E", 0, "*+?.()[]", true, 0, 8, NULL, 0);
    test_match_pattern("(?i)case", 0, "CASE", true, 0, 4, NULL, 0);
    test_match_pattern("(?i:case)sensitive", 0, "CASEsensitive", true, 0, 13, NULL, 0);
    test_match_pattern("(?i)c(?-i:ase)s", 0, "Cases", true, 0, 5, NULL, 0);
    test_match_pattern("(?i)c(?-i:ase)s", 0, "CASES", false, -1, -1, NULL, 0); // 'ase' case-sensitive

    printf("\n--- SECTION 15: Unicode & Real-World Matching ---\n");
    test_match_pattern("你好世界", 0, "你好世界", true, 0, 12, NULL, 0); // UTF-8 bytes
    test_match_pattern("a[α-ω]b", 0, "aβb", true, 0, 4, NULL, 0); // Greek letters (UTF-8)
    test_match_pattern("^([a-z0-9_\\.-]+)@([\\da-z\\.-]+)\\.([a-z\\.]{2,6})$", REG_EXTENDED,
        "user@example.com", true, 0, 16,
        (ExpectedCapture[]) { { 0, 4 }, { 5,12 }, { 13,16 }
    }, 3);
    test_match_pattern("^([a-z0-9_\\.-]+)@([\\da-z\\.-]+)\\.([a-z\\.]{2,6})$", REG_EXTENDED,
        "invalid@com", false, -1, -1, NULL, 0);
    test_match_pattern("https?://(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%_\\+.~#?&//=]*)", REG_EXTENDED,
        "http://www.example.com/path?query=1", true, 0, 35,
        (ExpectedCapture[]) { { 7, 11 }, { 22,35 }
    }, 2);

    printf("\n--- SECTION 16: Flag-Specific Matching ---\n");
    test_match_pattern("abc", REG_IGNORECASE, "AbC", true, 0, 3, NULL, 0);
    test_match_pattern("^abc$", REG_MULTILINE, "def\nabc\nghi", true, 4, 7, NULL, 0);
    test_match_pattern(".", REG_SINGLELINE, "a\nb", true, 0, 1, NULL, 0); // But . matches \n with singleline?
    test_match_pattern("a+?", REG_UNGREEDY, "aaa", true, 0, 3, NULL, 0); // Ungreedy flag makes ? default lazy


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

    return total_failures;
}
