// The C headers that Swift code imports as the module CFido2 (see module.modulemap).
// On macOS the Makefile prepares them in Build/obj/phido2-macos/deps/include; on Linux they
// come from the distribution's development packages.
#include <fido.h>
#include <fido/credman.h>
// libcbor decodes the CTAP2 responses that `monitor` observes.
#include <cbor.h>
// SHA-256, for comparing relying party ID hashes. libcrypto is linked anyway: libfido2 needs it.
#include <openssl/sha.h>

// Reusing one user verification for a whole credential listing needs the PIN/UV auth token
// functions, which older libfido2 releases (such as those in Ubuntu) do not have. With such
// a release these two do nothing, and libfido2 verifies the user for every query instead:
// invisible with a PIN, one more touch per relying party with a fingerprint.
#ifdef FIDO_PUAT_CREDMAN
static inline int phido2_get_credman_token(fido_dev_t *dev, const char *pin) {
    return fido_dev_get_puat(dev, FIDO_PUAT_CREDMAN, NULL, pin);
}
static inline void phido2_clear_token(fido_dev_t *dev) {
    fido_dev_set_puat(dev, NULL, 0);
}
#else
static inline int phido2_get_credman_token(fido_dev_t *dev, const char *pin) {
    (void)dev;
    (void)pin;
    return FIDO_OK;
}
static inline void phido2_clear_token(fido_dev_t *dev) {
    (void)dev;
}
#endif
