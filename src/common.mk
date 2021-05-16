#
# Copyright 2021 Santanu Sen. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution.
#

SRCDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
INCDIR := $(SRCDIR)../include
CXXFLAGS := $(CXXFLAGS) \
	-Wall -Wextra -Werror \
	-Wmissing-include-dirs -Wlogical-op -Wshadow \
	-Wmissing-declarations -Wunreachable-code -Wredundant-decls \
	-Wcast-qual -Wcast-align -Wsign-promo \
	-Woverloaded-virtual -Wctor-dtor-privacy -Wstrict-null-sentinel \
	-Wstrict-overflow=5 -Wswitch-default -Wundef \
	-Wnoexcept \
	-pedantic-errors -fno-elide-constructors \
	-g -fPIC -I $(INCDIR)
LDFLAGS_SO := $(LDFLAGS) -shared

TOPTARGETS := all clean

SUBDIRS := $(patsubst %/.,%,$(wildcard */.))

$(TOPTARGETS) : $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

SRCS = $(wildcard *.cpp)

OBJS = $(SRCS:.cpp=.o )

all: $(OBJS)

clean:
	rm -f *.o *.ii

.PHONY: $(TOPTARGETS) $(SUBDIRS)

.SUFFIXES: .ii
%.ii: %.cpp
	$(CXX) $(CXXFLAGS) -E -o $@ $<
