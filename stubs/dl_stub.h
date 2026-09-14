#ifndef DL_STUB_H
#define DL_STUB_H
#include <stddef.h>
#define RTLD_NOW 2
static inline void *dlopen(const char *f, int m) { (void)f; (void)m; return NULL; }
static inline void *dlsym(void *h, const char *s) { (void)h; (void)s; return NULL; }
static inline int dlclose(void *h) { (void)h; return 0; }
static inline char *dlerror(void) { return "static build"; }
#endif
