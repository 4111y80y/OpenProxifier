#ifndef LOCAL_PROXY_H
#define LOCAL_PROXY_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize and cleanup
bool LocalProxy_Init(void);
void LocalProxy_Cleanup(void);

// Start/Stop local proxy server
bool LocalProxy_Start(uint16_t port);
void LocalProxy_Stop(void);

#ifdef __cplusplus
}
#endif

#endif // LOCAL_PROXY_H
