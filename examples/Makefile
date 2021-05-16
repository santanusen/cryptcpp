#
# Copyright 2021 Santanu Sen. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution.
#

CXXFLAGS := $(CXXFLAGS) -g -I ../include
LDFLAGS := $(LDFLAGS) -L ../src -lcryptcpp -lcrypto -lssl

ALL_BINS := $(patsubst %.cpp,%.out,$(wildcard *.cpp))

all: $(ALL_BINS)

%.out: %.cpp
	$(CXX) $< $(CXXFLAGS) $(LDFLAGS) -o $@

clean:
	rm -f $(ALL_BINS)

run_codec_test: codec_test.out
	LD_LIBRARY_PATH="$$LD_LIBRARY_PATH:../src" ./codec_test.out

.PHONY: all clean run_codec_test
