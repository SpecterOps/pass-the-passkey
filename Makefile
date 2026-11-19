# Builds the native phido2 tool for the operating system this runs on.
#
#   make            build the tool
#   make test       run its unit tests
#   make clean      remove its build products
#   make distclean  also remove its prepared dependencies
#
# The work is done by the Makefile of the matching project in Src; every goal is passed on
# to it. Output goes to Build/, as with the .NET projects, which are built separately with
# `dotnet build` and are not touched by this file.

OS := $(shell uname -s)
ifeq ($(OS),Darwin)
PROJECT := Src/phido2-macos
else ifeq ($(OS),Linux)
PROJECT := Src/phido2-linux
endif

ifeq ($(wildcard $(PROJECT)/Makefile),)
$(error There is no phido2 project to build on $(OS) yet)
endif

.DEFAULT_GOAL := all
.PHONY: all test clean distclean

all test clean distclean:
	@$(MAKE) -C $(PROJECT) $@
