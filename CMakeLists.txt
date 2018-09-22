cmake_minimum_required(VERSION 2.8)
project(enee457_project2 C)

set(CMAKE_C_STANDARD 99)
include_directories(/usr/local/Cellar/openssl/1.0.2p/include)
include_directories(/usr/local/ssl/include)
add_executable(enee457_project2 main.c task4.h)
target_link_libraries(enee457_project2 crypto)