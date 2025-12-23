cmake_minimum_required(VERSION 3.30)
project(libdave-jvm LANGUAGES CXX C)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# if we're on clang or gcc, enable prefix mapping
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
  set(_prefix_map_opt "-frandom-seed=0 -ffile-prefix-map=\"${CMAKE_SOURCE_DIR}\"=. -fmacro-prefix-map=\"${CMAKE_SOURCE_DIR}\"=.")
  set(_common_flags "-flto=full -fvisibility=hidden")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_prefix_map_opt} ${_common_flags}")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_prefix_map_opt} ${_common_flags}")
  # TODO: how to pass these to vcpkg?
endif()

option(REQUIRE_BORINGSSL "Require BoringSSL instead of OpenSSL" ON)
option(TESTING "Build tests" OFF)
option(PERSISTENT_KEYS "Enable storage of persistent signature keys" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)

add_subdirectory(libdave/cpp)

find_package(JNI)
if(NOT JNI_FOUND)
  message(FATAL_ERROR "JNI not found - did you forget to set JAVA_HOME?")
endif()

set(DJ_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp)
add_library(dave-jvm SHARED
  ${DJ_ROOT}/bind_decryptor.cpp
  ${DJ_ROOT}/bind_encryptor.cpp
  ${DJ_ROOT}/bind_key_ratchet.cpp
  ${DJ_ROOT}/bind_session.cpp
)

target_link_libraries(dave-jvm PRIVATE libdave JNI::JNI)
target_compile_features(dave-jvm PRIVATE cxx_std_17)
