# Builds the native phido2 tool for the operating system this runs on (macOS or Linux).
#
#   make            build the tool
#   make test       run its unit tests
#   make clean      remove its build products
#   make distclean  also remove its prepared dependencies
#
# The work is done by the Makefile of the project in Src/phido2, which handles both systems;
# every goal is passed on to it. Output goes to Build/, as with the .NET projects, which
# are built separately with `dotnet build` and are not touched by this file.

PROJECT := Src/phido2

.DEFAULT_GOAL := all
.PHONY: all test clean distclean

all test clean distclean:
	@$(MAKE) -C $(PROJECT) $@
