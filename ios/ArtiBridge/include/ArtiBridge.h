// C interface of the arti-bridge static library (Rust, see ../src/lib.rs).
// Functions returning `char *` return a JSON object to release with arti_bridge_string_free.
// All calls except arti_bridge_status / set_dormant / shutdown / string_free may block: never call them on the main thread.

#ifndef ARTI_BRIDGE_H
#define ARTI_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void arti_bridge_init_logging(const char *filter);
char *arti_bridge_version(void);
char *arti_bridge_bootstrap(const char *state_dir, const char *cache_dir);
/// The 32-byte x25519 client key of a restricted onion service (from the pairing QR code).
char *arti_bridge_set_onion_auth(const char *host, const uint8_t *secret, size_t secret_len);
char *arti_bridge_status(void);
char *arti_bridge_http_get(const char *host, uint16_t port, const char *path, uint64_t timeout_ms);
char *arti_bridge_http_request(const char *host, uint16_t port, const char *method, const char *path,
                               const uint8_t *body, size_t body_len, uint64_t timeout_ms);
void arti_bridge_set_dormant(bool dormant);
void arti_bridge_shutdown(void);
void arti_bridge_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif
