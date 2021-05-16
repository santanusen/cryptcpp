#
# Copyright 2021 Santanu Sen. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution.
#

include ./common.mk

SOLIB := libcryptcpp.so

all : $(SOLIB)

SRCDIRS := common impl/openssl

SRCLIST := $(wildcard $(patsubst %,$(SRCDIR)%/*.cpp,$(SRCDIRS)))
OBJLIST := $(patsubst %.cpp,%.o,$(SRCLIST))

$(SOLIB) : $(SUBDIRS) $(OBJLIST)
	$(CXX) $(LDFLAGS_SO) -o $@ $(OBJLIST)

clean: soclean

soclean:
	rm -f $(SOLIB)

.PHONY: soclean
