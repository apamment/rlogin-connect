cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_FLAGS "-std=c++17 -g")
project(rlogin-connect)

add_executable(rlogin-connect main.cpp Rlogin.cpp)