cmake_minimum_required(VERSION 3.0.0)
project(dllexportlist VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(dllexportlist main.cpp pedll.cpp)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
