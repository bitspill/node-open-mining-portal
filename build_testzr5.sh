#!/bin/bash
g++ zr5test.cpp ./build/Release/obj.target/multihashing/zr5.o \
./build/Release/obj.target/multihashing/sha3/sph_blake.o \
./build/Release/obj.target/multihashing/sha3/sph_groestl.o \
./build/Release/obj.target/multihashing/sha3/sph_jh.o \
./build/Release/obj.target/multihashing/sha3/sph_keccak.o \
./build/Release/obj.target/multihashing/sha3/sph_skein.o \
 -o testzr5
