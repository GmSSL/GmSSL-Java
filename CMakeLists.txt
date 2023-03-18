cmake_minimum_required(VERSION 3.2)
project(gmssljni)

#find_package(Java REQUIRED)
#find_package(JNI REQUIRED)
#include_directories(${JNI_INCLUDE_DIRS})
#include(UseJava)
include_directories(jni)
include_directories(/usr/local/include)

add_library(gmssljni SHARED gmssljni.c)
target_link_libraries(gmssljni ${JNI_LIBRARIES})
target_link_libraries(gmssljni -L/usr/local/lib)
target_link_libraries(gmssljni gmssl)

target_include_directories(gmssljni PUBLIC ${CMAKE_SOURCE_DIR}/src/include)

enable_testing()
