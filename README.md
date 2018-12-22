rust-beep
=========

This repository makes [libvortex](https://github.com/ASPLes/libvortex-1.1)
usable from Rust.

It's not a real wrapper around the library as the code has been copied over into
this repository and uses a new CMake build. This was done to get an easier build
for the libaxl and libvortex code especially when doing a cross compile. There
is no need to build the libraries on their own as `cargo` will take care of
building the C code as well.

The Rust APIs are limited so far, only providing the base functionality that I
need myself. Further extensions of functionality coverage is desired.

Note: I don't expect the build to succeed on non-UNIX at the moment.
