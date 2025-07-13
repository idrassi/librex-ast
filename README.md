# librex-ast

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**librex-ast** is a feature-rich, PCRE/Perl-compatible regular expression parser written in modern C.

Unlike regex *engines* that match text, `librex-ast` is a **parser**. It takes a regex pattern as input and produces a detailed **Abstract Syntax Tree (AST)** that represents its logical structure. This makes it an ideal foundation for building custom regex engines, compilers, transpilers, static analysis tools, or educational software.

---

### ⚠️ Project Status: Educational & Experimental

This library is a comprehensive implementation of modern regex syntax and is an excellent resource for learning about parsing techniques. However, before using it in a production environment, please be aware of the following:

*   **Not Thread-Safe:** The current implementation uses a global cache for Unicode properties, making it unsafe for concurrent use across multiple threads.
*   **Simplified Unicode Properties:** The `\p{...}` property support is framework-ready but uses a simplified, non-exhaustive set of Unicode data for demonstration. A production-ready version would require data generated from the full Unicode Character Database (UCD).
*   **API Ergonomics:** The API is fully functional but exposes internal memory management details (the `AstArena`). A future version will hide this behind an opaque handle for a cleaner user experience.

Contributions to address these points are highly welcome!

---

### Key Features

*   **Extensive PCRE/Perl Syntax Support:** Parses a wide array of constructs beyond basic regex.
*   **Detailed AST:** Generates a clean, navigable Abstract Syntax Tree for deep pattern analysis.
*   **Advanced Grouping:** Full support for named/numbered capture groups, atomic groups (`(?>...)`), branch-reset groups (`(?|...)`), and more.
*   **Assertions & Conditionals:** Correctly parses lookaheads, lookbehinds, and conditional subpatterns (`(?(cond)...)`).
*   **Subroutines & Recursion:** Handles subroutine calls (`(?1)`, `(?&name)`) and full pattern recursion (`(?R)`).
*   **Unicode-Aware:** Parses UTF-8 patterns, Unicode escape sequences (`\x{...}`), and Unicode properties (`\p{L}`).
*   **Efficient Memory Management:** Uses an arena allocator for fast, bulk allocation of AST nodes, minimizing `malloc` overhead.
*   **Comprehensive Error Reporting:** Provides clear, human-readable error messages with line and column numbers.
*   **Zero Dependencies:** Written in pure C11 with no external library dependencies.

---

### Usage Example

Here is a simple example of how to parse a pattern and print its AST.

```c
#include <stdio.h>
#include <stdlib.h>
#include "regex-parser.h"

int main(void) {
    const char* pattern = "(?<year>\\d{4})-(?<month>\\d{2})-(?<day>\\d{2})";
    char* error_msg = NULL;
    AstArena* arena = NULL;

    // Parse the regular expression
    RegexNode* ast = regex_parse(pattern, 0, &arena, &error_msg);

    if (ast) {
        printf("Successfully parsed pattern: \"%s\"\n", pattern);
        printf("--- AST ---\n");
        print_regex_ast(ast);
        printf("-----------\n");

        // Clean up the AST and the arena
        regex_free_result(ast, arena);
    } else {
        fprintf(stderr, "Failed to parse pattern.\n");
        fprintf(stderr, "Error: %s\n", error_msg);
        free(error_msg); // The error message is malloc'd
    }
    
    // Recommended cleanup for global caches
    regex_cleanup_property_cache();

    return 0;
}
```

### API Reference

*   `RegexNode* regex_parse(const char* pattern, uint32_t flags, AstArena** arena, char** error_msg)`
    Parses a null-terminated `pattern` string. On success, returns the root `RegexNode` of the AST and populates `*arena`. On failure, returns `NULL` and allocates an error message in `*error_msg`. The caller is responsible for freeing `error_msg`.

*   `void regex_free_result(RegexNode* node, AstArena* arena)`
    Frees all memory associated with a successful parse result, including the AST nodes and the arena itself.

*   `void print_regex_ast(const RegexNode* node)`
    A debugging utility to print a human-readable representation of the AST to standard output.

*   `void regex_cleanup_property_cache(void)`
    Frees memory used by the global Unicode property cache.

*   **Flags:** `REG_IGNORECASE`, `REG_MULTILINE`, `REG_SINGLELINE`, `REG_EXTENDED`, `REG_UNGREEDY`.

---

### Supported Regex Syntax

#### Basic Elements
- Literal characters (including full Unicode support)
- `.` (dot metacharacter)
- Character classes `[abc]`, `[^abc]`, `[a-z]`
- Pre-defined classes: `\d`, `\D`, `\w`, `\W`, `\s`, `\S`
- Anchors: `^`, `$`, `\A`, `\z`, `\b` (word boundary), `\B`

#### Quantifiers
- Greedy: `*`, `+`, `?`, `{n,m}`
- Lazy (non-greedy): `*?`, `+?`, `??`, `{n,m}?`
- Possessive: `*+`, `++`, `?+`, `{n,m}+`

#### Groups
- Capturing groups: `(...)`
- Non-capturing groups: `(?:...)`
- Named groups: `(?<name>...)`
- Atomic groups: `(?>...)`
- Branch-reset groups: `(?|...)`

#### Assertions
- Positive Lookahead: `(?=...)`
- Negative Lookahead: `(?!...)`
- Positive Lookbehind: `(?<=...)` (fixed-length only)
- Negative Lookbehind: `(?<!...)` (fixed-length only)

#### Backreferences & Subroutines
- Numbered backreferences: `\1`, `\2`
- Named backreferences: `\k<name>`
- Numbered subroutine calls: `(?1)`, `(?2)`
- Named subroutine calls: `(?&name)`
- Full pattern recursion: `(?R)`

#### Conditionals
- Numeric condition: `(?(1)yes|no)`
- Named condition: `(?(<name>)yes|no)`
- Assertion condition: `(?((?=...))yes|no)`

#### Modifiers & Unicode
- Inline flags: `(?i)`, `(?-m)`
- Scoped flags: `(?i:...)`
- Unicode properties: `\p{L}`, `\P{Sc}`
- Unicode escapes: `\x{1F600}`

#### Other
- Comments: `(?#...)`
- Quoted sequences: `\Q...\E`
- POSIX character classes: `[[:alpha:]]`, `[[:digit:]]`, etc.

---

### Building

The project has no external dependencies. You can compile the parser and its test harness using a C99 compiler like GCC or Clang.

```bash
# Compile the parser with the test main
gcc -o test_parser regex-parser.c -DTEST_MAIN -Wall -Wextra -std=c99

# Run the test suite
./test_parser
```

---

### Roadmap & Contributing

This project was started as an exploration of modern regex parsing. Contributions are welcome to make it more robust and suitable for production use. High-priority areas include:

-   [ ] **Thread Safety:** Refactor the Unicode property cache to be thread-local or passed via a context struct, removing all global state.
-   [ ] **API Ergonomics:** Introduce an opaque `RegexParseResult` struct to hide the `AstArena` from the public API, simplifying the `create`/`destroy` lifecycle.
-   [ ] **Full Unicode Support:** Integrate code generation scripts to build comprehensive property and character-folding tables from the official Unicode Character Database (UCD).
-   [ ] **AST Optimization:** Add optional passes to simplify the AST (e.g., constant folding, merging character nodes).
-   [ ] **CI & Testing:** Expand the test suite and set up more comprehensive continuous integration checks.

Please feel free to open an issue to discuss a new feature or submit a pull request.

### License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

### Author

Mounir IDRASSI <mounir.idrassi@amcrypto.jp>
