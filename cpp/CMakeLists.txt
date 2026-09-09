cmake_minimum_required(VERSION 3.16)
project(slicebf_code_and_materials LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(MSVC)
  add_compile_options(/utf-8 $<$<CONFIG:Release>:/O2>)
  add_link_options($<$<CONFIG:Release>:/OPT:REF,NOICF>)
else()
  add_compile_options($<$<CONFIG:Release>:-O3>)
endif()

find_package(OpenSSL REQUIRED)

add_library(slicebf_core src/crypto.cpp src/corpus.cpp src/slicebf.cpp)
target_include_directories(slicebf_core PUBLIC include third_party)
target_link_libraries(slicebf_core PUBLIC OpenSSL::Crypto)

add_executable(run_experiments apps/run_experiments.cpp)
target_link_libraries(run_experiments PRIVATE slicebf_core)

foreach(name protocol_smoke e9_correctness dyn_correctness)
  add_executable(${name} apps/${name}.cpp)
  target_link_libraries(${name} PRIVATE slicebf_core)
endforeach()

enable_testing()
add_test(NAME protected_protocol COMMAND protocol_smoke)
