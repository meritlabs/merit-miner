
AM_CXXFLAGS = -std=c++11 -march=native

if DEBUG
  AM_CXXFLAGS += -Wall -g -O3
else
  AM_CXXFLAGS += -Wall -O3
endif

noinst_LIBRARIES = libcuckoo.a

libcuckoo_a_SOURCES	= \
        blake2/blake2.h blake2/blake2-impl.h blake2/blake2b-ref.c \
				cuckoo.hpp cuckoo.cpp

