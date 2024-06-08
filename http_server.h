#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/workqueue.h>
#include <net/sock.h>

struct http_server_param {
    struct socket *listen_socket;
};

struct khttpd_service {
    bool is_stopped;
    struct list_head worker;
};

extern struct workqueue_struct *khttpd_wq;
extern int http_server_daemon(void *arg);

#endif
