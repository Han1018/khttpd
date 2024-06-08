#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/workqueue.h>
#include <net/sock.h>
#include "http_parser.h"

struct http_server_param {
    struct socket *listen_socket;
};

struct khttpd_service {
    bool is_stopped;
    struct list_head worker;
};

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context dir_context;
    struct list_head node;
    struct work_struct khttpd_work;
    void *timer_node;
};

extern struct workqueue_struct *khttpd_wq;
extern int http_server_daemon(void *arg);

#endif
