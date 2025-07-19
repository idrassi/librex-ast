cmake_minimum_required(VERSION 3.10)
project(librex_ast C)

set(CMAKE_C_STANDARD 99)

# Core library source files
set(LIB_SRC regex-parser.c regex-match.c regex-unicode.c)

# Test source file
set(TEST_SRC regex-test.c)

# Create shared library
add_library(librex_ast_shared SHARED ${LIB_SRC})
target_compile_definitions(librex_ast_shared PRIVATE LIBREX_BUILD_DLL)

# Create static library
add_library(librex_ast_static STATIC ${LIB_SRC})

# Set library output names
set_target_properties(librex_ast_shared PROPERTIES OUTPUT_NAME "librex_ast")
set_target_properties(librex_ast_static PROPERTIES OUTPUT_NAME "librex_ast")

# Fix MSYS2/MinGW naming conventions
if(MSYS OR MINGW)
    # Remove the "lib" prefix and force .dll/.a extensions
    set_target_properties(librex_ast_shared PROPERTIES 
        PREFIX ""
        SUFFIX ".dll"
        ARCHIVE_OUTPUT_NAME "librex_ast.dll"
    )
    set_target_properties(librex_ast_static PROPERTIES 
        PREFIX ""
        SUFFIX ".a"
    )
    
    # Prevent MSYS2 from adding "msys-" prefix
    set_target_properties(librex_ast_shared PROPERTIES 
        RUNTIME_OUTPUT_NAME "librex_ast"
        LIBRARY_OUTPUT_NAME "librex_ast"
    )
endif()

# Create test executable
add_executable(regex_test ${TEST_SRC})

# Link test executable to static library
target_link_libraries(regex_test librex_ast_static)

# Enable TEST_MAIN for test harness
target_compile_definitions(regex_test PRIVATE TEST_MAIN)

# Static C runtime linking on Windows
if(WIN32 AND MSVC)
    target_compile_options(librex_ast_shared PRIVATE /MT)
    target_compile_options(librex_ast_static PRIVATE /MT)
    target_compile_options(regex_test PRIVATE /MT)
endif()

# Optionally allow user to specify extra flags
option(ENABLE_WARNINGS "Enable extra compiler warnings" ON)
if(ENABLE_WARNINGS)
    if (MSVC)
        target_compile_options(librex_ast_shared PRIVATE /W4)
        target_compile_options(librex_ast_static PRIVATE /W4)
        target_compile_options(regex_test PRIVATE /W4)
    else()
        target_compile_options(librex_ast_shared PRIVATE -Wall -Wextra -pedantic)
        target_compile_options(librex_ast_static PRIVATE -Wall -Wextra -pedantic)
        target_compile_options(regex_test PRIVATE -Wall -Wextra -pedantic)
    endif()
endif()
