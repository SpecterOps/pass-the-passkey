# Builds phido2 for macOS: one self-contained, ad-hoc signed executable.
#
#   make            build and sign the release binary
#   make test       run the unit tests
#   make clean      remove build products (keeps the prepared dependencies)
#   make distclean  also remove the prepared dependencies
#
# Nothing is written into this folder. Everything goes to the repository's Build folder,
# next to the output of the .NET projects:
#
#   Build/bin/phido2-macos/release/   the final executable
#   Build/obj/phido2-macos/swiftpm/   SwiftPM's intermediate files
#   Build/obj/phido2-macos/deps/      headers and static libraries prepared by this Makefile
#
# VS Code's Swift extension builds for its own purposes into Build/obj/phido2-macos/vscode
# (see .vscode/settings.json). It must not share SwiftPM's folder with this Makefile: two
# builds in one folder overwrite each other's files.
#
# Needs Homebrew's libfido2 (`brew install libfido2`) and the Xcode Command Line Tools.

PRODUCT := phido2
PROJECT := phido2-macos

# Absolute, so that the paths mean the same to make, SwiftPM and the linker.
HERE    := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
BUILD   := $(abspath $(HERE)/../../Build)
BIN     := $(BUILD)/bin/$(PROJECT)/release
OBJ     := $(BUILD)/obj/$(PROJECT)
SCRATCH := $(OBJ)/swiftpm
# Must match `deps` in Package.swift.
DEPS    := $(OBJ)/deps

SWIFT_FLAGS := --package-path $(HERE) --scratch-path $(SCRATCH)

# With only the Command Line Tools selected (no Xcode), SwiftPM does not find the
# Swift Testing framework by itself.
CLT := /Library/Developer/CommandLineTools/Library/Developer
ifeq ($(shell xcode-select -p),/Library/Developer/CommandLineTools)
TEST_FLAGS := -Xswiftc -F$(CLT)/Frameworks -Xlinker -F$(CLT)/Frameworks \
	-Xlinker -rpath -Xlinker $(CLT)/Frameworks -Xlinker -rpath -Xlinker $(CLT)/usr/lib
endif

# Homebrew is only consulted by goals that build something.
ifeq ($(filter clean distclean,$(MAKECMDGOALS)),)
ifneq ($(shell brew list libfido2 >/dev/null 2>&1 && echo yes),yes)
$(error libfido2 is not installed; run "brew install libfido2" first)
endif
FIDO2   := $(shell brew --prefix libfido2)
CBOR    := $(shell brew --prefix libcbor)
OPENSSL := $(shell brew --prefix $$(brew deps libfido2 | grep '^openssl'))
# libcbor must be the version Homebrew's libfido2 was built against ("0.15.0_1" -> "0.15.0").
CBOR_VERSION := $(shell brew list --versions libcbor | awk '{print $$2}' | cut -d_ -f1)
endif
CBOR_SRC := $(DEPS)/src/libcbor-$(CBOR_VERSION)
CBOR_OBJ := $(DEPS)/src/cbor-obj

.PHONY: all deps test clean distclean

all: deps
	swift build $(SWIFT_FLAGS) -c release
	mkdir -p $(BIN)
	cp -f "$$(swift build $(SWIFT_FLAGS) -c release --show-bin-path)/$(PRODUCT)" $(BIN)/$(PRODUCT)
	codesign --force --sign - --identifier $(PRODUCT) $(BIN)/$(PRODUCT)
	@echo "Built $(BIN)/$(PRODUCT)"

test: deps
	swift test $(SWIFT_FLAGS) $(TEST_FLAGS)

clean:
	rm -rf $(SCRATCH) $(BUILD)/bin/$(PROJECT)

distclean: clean
	rm -rf $(OBJ)

# --- Dependencies -----------------------------------------------------------
# $(DEPS)/lib holds static archives only, so the linker cannot pick a dylib and
# the executable ends up with no non-system dynamic dependencies.
# SwiftPM does not track these archives, so each rule also deletes the linked
# product to force a relink.

deps: $(DEPS)/lib/libfido2.a $(DEPS)/lib/libcrypto.a $(DEPS)/lib/libcbor.a
	@mkdir -p $(DEPS)/include
	@ln -sfn $(FIDO2)/include/fido.h $(DEPS)/include/fido.h
	@ln -sfn $(FIDO2)/include/fido $(DEPS)/include/fido
	@ln -sfn $(OPENSSL)/include/openssl $(DEPS)/include/openssl
	@ln -sfn $(CBOR)/include/cbor.h $(DEPS)/include/cbor.h
	@ln -sfn $(CBOR)/include/cbor $(DEPS)/include/cbor

$(DEPS)/lib/libfido2.a: $(FIDO2)/lib/libfido2.a
	@mkdir -p $(@D)
	cp -f $< $@
	@rm -f $(SCRATCH)/release/$(PRODUCT)

$(DEPS)/lib/libcrypto.a: $(OPENSSL)/lib/libcrypto.a
	@mkdir -p $(@D)
	cp -f $< $@
	@rm -f $(SCRATCH)/release/$(PRODUCT)

# Homebrew ships libcbor as a dylib only, so the same version is compiled statically.
# The stamp lives in the versioned source folder: a libcbor upgrade means a new folder,
# a new stamp, and therefore a rebuilt archive.
$(CBOR_SRC)/.extracted:
	@mkdir -p $(DEPS)/src
	curl -fsSL https://github.com/PJK/libcbor/archive/refs/tags/v$(CBOR_VERSION).tar.gz | tar xz -C $(DEPS)/src
	@touch $@

# configuration.h and cbor_export.h are cmake-generated; Homebrew's copies are reused.
$(DEPS)/lib/libcbor.a: $(CBOR_SRC)/.extracted
	@mkdir -p $(@D) $(CBOR_OBJ)
	@rm -f $(CBOR_OBJ)/*.o $@
	@echo "Compiling static libcbor $(CBOR_VERSION)"
	@for c in $(CBOR_SRC)/src/*.c $(CBOR_SRC)/src/cbor/*.c $(CBOR_SRC)/src/cbor/internal/*.c; do \
		clang -O2 -c -I$(CBOR_SRC)/src -I$(CBOR)/include $$c -o $(CBOR_OBJ)/$$(basename $$c .c).o || exit 1; \
	done
	ar rcs $@ $(CBOR_OBJ)/*.o
	@rm -f $(SCRATCH)/release/$(PRODUCT)
