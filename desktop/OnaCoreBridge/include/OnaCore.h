// C interface of the ona-core-bridge static library (Rust, see ../src/lib.rs).
#ifndef ONA_CORE_H
#define ONA_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OnaCore OnaCore;

OnaCore *ona_core_new(void);
void ona_core_free(OnaCore *core);
/// JSON command in, JSON reply out (release it with ona_core_string_free). Blocking: not on the main thread.
char *ona_core_dispatch(OnaCore *core, const char *request);
void ona_core_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif
