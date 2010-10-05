# This makefile is used only if you run GNU Make.
# It is necessary if you modify files in the m4/ directory or
# want to build targets usually of interest only to the maintainer.

have-Makefile := $(shell test -f Makefile && echo yes)

# If the user runs GNU make but has not yet run ./configure,
# give them a diagnostic.
ifeq ($(have-Makefile),yes)

export VERBOSE = yes
include Makefile

else

all:
       @echo There seems to be no Makefile in this directory.
       @echo "You must run ./configure before running \`make'."
       @exit 1

endif
