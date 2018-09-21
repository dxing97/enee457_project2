cmake_minimum_required(VERSION 3.12)
project(enee457_project2 C)

set(CMAKE_C_STANDARD 99)
include_directories(/usr/local/Cellar/openssl/1.0.2p/include)
add_executable(enee457_project2 main.c task4.h)
target_link_libraries(enee457_project2 ssl)