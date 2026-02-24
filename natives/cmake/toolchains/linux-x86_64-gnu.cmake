# Native or generic x86_64 Linux (glibc). Use on ubuntu-22.04 runner without cross-compilation.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_STRIP strip)
set(CMAKE_AR gcc-ar)
set(CMAKE_NM gcc-nm)
set(CMAKE_RANLIB gcc-ranlib)