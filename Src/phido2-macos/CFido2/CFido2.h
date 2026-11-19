// The C headers that Swift code imports as the module CFido2 (see module.modulemap).
// The Makefile prepares them in Build/obj/phido2-macos/deps/include.
#include <fido.h>
#include <fido/credman.h>
// libcbor decodes the CTAP2 responses that `monitor` observes.
#include <cbor.h>
