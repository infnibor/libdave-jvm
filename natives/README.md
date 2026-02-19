# libdave-jvm - native libraries

This directory contains the native libraries for the libdave-jvm project.

We vendor everything using [git-subrepo](https://github.com/ingydotnet/git-subrepo). No internet access or external build tools like `vcpkg` are required.

## Patches

### Markers

We use the following markers to mark changes:

**In C/C++ files:**
```c
/// KOE PATCH BEGIN
/// KOE PATCH END
```

**In CMake files:**
```cmake
## KOE PATCH BEGIN
## KOE PATCH END
```

### Current patches

- [dave/dave.h](libdave/cpp/includes/dave/dave.h): Disabled symbol exports, as we only want to export the JNI symbols.