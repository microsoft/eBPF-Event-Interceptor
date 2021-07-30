#include "common.h"

#define FN_NAME "tcp_set_state"

#ifdef __cplusplus
extern "C" {
#endif

extern void AddProbe(const char *BPF_PROGRAM) ;
extern int setupBPF(const char *BPF_PROGRAM) ;
struct tcp_event_t  DequeuePerfEvent();
extern void printCharArray(const char * charPtr);
extern void cleanup();
extern unsigned getStatus();

#ifdef __cplusplus
}
#endif

