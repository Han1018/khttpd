#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "http_parser.h"
#include "http_server.h"

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256

#define MODULE_NAME "khttpd"

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context dir_context;
};

struct khttpd_service daemon = {.is_stopped = false};
struct workqueue_struct *khttpd_wq;  // define khttpd workqueue

static bool handle_directory(struct http_request *request);

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    int ret = 0;
    ret = handle_directory(request);
    if (ret == 0) {
        pr_err("handle_directory failed\n");
        return -1;
    }
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}
// callback for 'iterate_dir', trace entry.
static _Bool tracedir(struct dir_context *dir_context,
                      const char *name,
                      int namelen,
                      loff_t offset,
                      u64 ino,
                      unsigned int d_type)
{
    if (strcmp(name, ".") && strcmp(name, "..")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[SEND_BUFFER_SIZE] = {0};

        int len =
            snprintf(buf, SEND_BUFFER_SIZE,
                     "<tr><td><a href=\"%s\">%s</a></td></tr>\r\n", name, name);
        if (len >= SEND_BUFFER_SIZE)  // avoid buffer not enough
            pr_err("Buffer truncated, required size: %d\n", len);

        http_server_send(request->socket, buf, strlen(buf));
    }
    return true;
}

static bool handle_directory(struct http_request *request)
{
    struct file *fp;
    char buf[SEND_BUFFER_SIZE] = {0};

    request->dir_context.actor = tracedir;
    if (request->method != HTTP_GET) {
        snprintf(buf, SEND_BUFFER_SIZE,
                 "HTTP/1.1 501 Not Implemented\r\n%s%s%s%s",
                 "Content-Type: text/plain\r\n", "Content-Length: 19\r\n",
                 "Connection: Close\r\n", "501 Not Implemented\r\n");
        http_server_send(request->socket, buf, strlen(buf));
        return false;
    }

    snprintf(buf, SEND_BUFFER_SIZE, "HTTP/1.1 200 OK\r\n%s%s%s",
             "Connection: Keep-Alive\r\n", "Content-Type: text/html\r\n",
             "Keep-Alive: timeout=5, max=1000\r\n\r\n");
    http_server_send(request->socket, buf, strlen(buf));


    snprintf(buf, SEND_BUFFER_SIZE, "%s%s%s%s", "<html><head><style>\r\n",
             "body{font-family: monospace; font-size: 15px;}\r\n",
             "td {padding: 1.5px 6px;}\r\n",
             "</style></head><body><table>\r\n");
    http_server_send(request->socket, buf, strlen(buf));

    fp = filp_open("/home/deepcat/Documents/Course/linux2024/khttpd",
                   O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(fp)) {
        pr_info("Open file failed");
        return false;
    }

    iterate_dir(fp, &request->dir_context);
    snprintf(buf, SEND_BUFFER_SIZE, "</table></body></html>\r\n");
    http_server_send(request->socket, buf, strlen(buf));
    filp_close(fp, NULL);
    return true;
}

// static int http_server_worker(void *arg)
static void http_server_worker(struct work_struct *work)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct khttpd *khttpd_work = container_of(work, struct khttpd, khttpd_work);
    struct socket *socket = khttpd_work->sock;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    while (!kthread_should_stop()) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    // return 0;
}

static struct work_struct *create_work(struct socket *sk)
{
    struct khttpd *work;

    // GFP_KERNEL: 正常配置記憶體
    if (!(work = kmalloc(sizeof(struct khttpd), GFP_KERNEL)))
        return NULL;

    work->sock = sk;

    // 建立 work - http_server_worker function
    INIT_WORK(&work->khttpd_work, http_server_worker);
    list_add(&work->list, &daemon.worker);  // Add work to worker list

    return &work->khttpd_work;
}

static void free_work(void)
{
    struct khttpd *tmp, *tgt;
    list_for_each_entry_safe (tgt, tmp, &daemon.worker, list) {
        kernel_sock_shutdown(tgt->sock, SHUT_RDWR);
        flush_work(&tgt->khttpd_work);
        sock_release(tgt->sock);
        kfree(tgt);
    }
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct http_server_param *param = (struct http_server_param *) arg;
    struct work_struct *work;

    // Initialize CMWQ
    khttpd_wq = alloc_workqueue(MODULE_NAME, WQ_UNBOUND, 0);
    if (!khttpd_wq) {
        pr_err("can't create workqueue\n");
        return -ENOMEM;
    }
    INIT_LIST_HEAD(&daemon.worker);  // Initialize list head

    // 登記要接收的 signal
    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            // 檢查此 thread 是否有 signal 發生
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

        // create work
        work = create_work(socket);
        if (!work) {
            pr_err("can't create work\n");
            continue;
        }

        queue_work(khttpd_wq, work);  // Add work to workqueue
    }

    daemon.is_stopped = true;

    // free work and destroy workqueue
    free_work();
    destroy_workqueue(khttpd_wq);

    return 0;
}
