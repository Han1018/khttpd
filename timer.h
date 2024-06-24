#ifndef TIMER_H
#define TIMER_H

#include "hash_content.h"
#include "http_server.h"

#define TIMEOUT_DEFAULT 8000 /* ms */

typedef int (*timer_callback)(void *);
typedef struct {
    size_t key;
    size_t pos;
    timer_callback callback;
    void *object;
} timer_node_t;

void http_timer_init(void);
int http_find_timer(void);
void handle_expired_timers(void);
bool http_add_timer(void *object,
                    size_t timeout,
                    timer_callback cb,
                    bool is_socket);
void http_timer_update(timer_node_t *node, size_t timeout);
void http_free_timer(void);

#endif