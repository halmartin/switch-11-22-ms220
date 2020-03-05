# This script serves following purpose:
#
# 1. It generates native version information by querying
#    automerger maintained database to see where src/include
#    came from
# 2. For select components, as listed in compvers.sh
#    it generates component version files
#
# Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
# 
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#

SRCBASE := ..

TARGETS := epivers.h

ifdef VERBOSE
export VERBOSE
endif

all release: epivers compvers

# Generate epivers.h for native branch version
epivers:
	bash epivers.sh

# Generate epivers.h for native branch version
compvers:
	@if [ -s "compvers.sh" ]; then \
		echo "Generating component versions, if any"; \
		bash compvers.sh; \
	else \
		echo "Skipping component version generation"; \
	fi

# Generate epivers.h for native branch version
clean_compvers:
	@if [ -s "compvers.sh" ]; then \
		echo "bash compvers.sh clean"; \
		bash compvers.sh clean; \
	else \
		echo "Skipping component version clean"; \
	fi

clean:
	rm -f $(TARGETS) *.prev

clean_all: clean clean_compvers

.PHONY: all release clean epivers compvers clean_compvers
