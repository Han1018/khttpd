#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/workqueue.h>
#include <net/sock.h>
#include "compress.h"
#include "http_parser.h"

#define SEND_BUFFER_SIZE 256

struct http_server_param {
    struct socket *listen_socket;
    char *root_path;
};

struct khttpd_service {
    bool is_stopped;
    struct list_head worker;
    char *root_path;
};

struct cache_content {
    struct list_head cache;
    char buf[SEND_BUFFER_SIZE];
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
    struct list_head *cache_list;
};

extern struct workqueue_struct *khttpd_wq;
extern int http_server_daemon(void *arg);

#endif
