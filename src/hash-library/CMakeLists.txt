
cmake_minimum_required(VERSION 2.8)
project(HashLibrary)

file(GLOB libHash_SOURCES *.cpp)
file(GLOB libHash_HEADERS *.h)

add_library(${libHash_HEADERS} ${libHash_SOURCES})

if(${UNIX})
#  set(CMAKE_CXX_FLAGS "-std=c++11")
  set(CMAKE_CXX_FLAGS "-fPIC")
elseif(${WINDOWS})
  set(CMAKE_CXX_FLAGS "/MP /EHsc")
endif(${UNIX})
