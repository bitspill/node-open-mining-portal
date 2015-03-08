#!/bin/bash
g++ -g -DTEST_VERBOSELY zr5test.cpp zr5.c \
./build/Release/obj.target/multihashing/sha3/sph_blake.o \
./build/Release/obj.target/multihashing/sha3/sph_groestl.o \
./build/Release/obj.target/multihashing/sha3/sph_jh.o \
./build/Release/obj.target/multihashing/sha3/sph_keccak.o \
./build/Release/obj.target/multihashing/sha3/sph_skein.o \
 -o testzr5
