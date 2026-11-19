cmake_minimum_required(VERSION 3.20)
project(NTDSecScanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Point CMake to Homebrew LLVM
execute_process(COMMAND brew --prefix llvm OUTPUT_VARIABLE LLVM_PREFIX OUTPUT_STRIP_TRAILING_WHITESPACE)
list(APPEND CMAKE_PREFIX_PATH "${LLVM_PREFIX}/lib/cmake/llvm" "${LLVM_PREFIX}/lib/cmake/clang")

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_executable(sec-scanner scanner.cpp)

target_link_libraries(sec-scanner
  PRIVATE
  clangTooling
  clangBasic
  clangASTMatchers
)
