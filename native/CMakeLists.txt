cmake_minimum_required(VERSION 3.20)

project(vulsor_clang_analysis LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(
    -mcmodel=large
)

set(CLANG_ROOT "" CACHE PATH "Clang/LLVM installation prefix")

if(NOT CLANG_ROOT)
    message(FATAL_ERROR
        "CLANG_ROOT must point to the Clang/LLVM installation prefix"
    )
endif()

set(CLANG_INCLUDE_DIR "${CLANG_ROOT}/include")
set(CLANG_LIBRARY_DIR "${CLANG_ROOT}/lib")

if(NOT EXISTS "${CLANG_INCLUDE_DIR}/clang/AST/ASTContext.h")
    message(FATAL_ERROR
        "Clang AST headers not found under: ${CLANG_INCLUDE_DIR}"
    )
endif()

if(NOT EXISTS "${CLANG_INCLUDE_DIR}/clang/Analysis/CFG.h")
    message(FATAL_ERROR
        "Clang CFG headers not found under: ${CLANG_INCLUDE_DIR}"
    )
endif()

if(NOT EXISTS "${CLANG_INCLUDE_DIR}/llvm/Frontend/OpenMP/OMP.inc")
    message(FATAL_ERROR
        "LLVM OpenMP generated header not found under: ${CLANG_INCLUDE_DIR}"
    )
endif()

find_library(CLANG_CPP_LIBRARY
    NAMES clang-cpp
    PATHS "${CLANG_LIBRARY_DIR}"
    NO_DEFAULT_PATH
    REQUIRED
)

find_library(LLVM_SHARED_LIBRARY
    NAMES LLVM-21
    PATHS "${CLANG_LIBRARY_DIR}"
    NO_DEFAULT_PATH
    REQUIRED
)

add_executable(clang_analysis
    clang_analysis.cpp
)

target_include_directories(clang_analysis
    PRIVATE
        "${CLANG_INCLUDE_DIR}"
)

target_link_libraries(clang_analysis
    PRIVATE
        "${CLANG_CPP_LIBRARY}"
        "${LLVM_SHARED_LIBRARY}"
        ntdll
)

add_executable(clang_driver_probe
    clang_driver_probe.cpp
)

target_include_directories(clang_driver_probe
    PRIVATE
        "${CLANG_INCLUDE_DIR}"
)

target_compile_options(clang_driver_probe
    PRIVATE
        -mcmodel=small
)

target_link_libraries(clang_driver_probe
    PRIVATE
        "${CLANG_CPP_LIBRARY}"
        "${LLVM_SHARED_LIBRARY}"
        ntdll
)

add_executable(rav_traversal_probe
    rav_traversal_probe.cpp
)

target_include_directories(rav_traversal_probe
    PRIVATE
        "${CLANG_INCLUDE_DIR}"
)

target_compile_options(rav_traversal_probe
    PRIVATE
        -mcmodel=large
)

target_link_libraries(rav_traversal_probe
    PRIVATE
        "${CLANG_CPP_LIBRARY}"
        "${LLVM_SHARED_LIBRARY}"
        ntdll
)