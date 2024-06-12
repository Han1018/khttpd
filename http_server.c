#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "http_server.h"
#include "mime_type.h"
#include "timer.h"

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256
#define BUFFER_SIZE 256

#define MODULE_NAME "khttpd"

#define SEND_HTTP_MSG(socket, buf, format, ...)           \
    snprintf(buf, SEND_BUFFER_SIZE, format, __VA_ARGS__); \
    http_server_send(socket, buf, strlen(buf));

struct khttpd_service daemon = {.is_stopped = false};
struct workqueue_struct *khttpd_wq;  // define khttpd workqueue

static bool handle_directory(struct http_request *request, int keep_alive);

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
    ret = handle_directory(request, keep_alive);
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
    memset(request->request_url, 0, 128);
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

static void catstr(char *res, char *first, char *second)
{
    int first_size = strlen(first);
    int second_size = strlen(second);
    memset(res, 0, BUFFER_SIZE);
    memcpy(res, first, first_size);
    memcpy(res + first_size, second, second_size);
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

        // create href link
        char *href_link = kmalloc(
            strlen(request->request_url) + strlen(name) + 2, GFP_KERNEL);
        if (strcmp(request->request_url, "/") != 0) {
            strncpy(href_link, request->request_url,
                    strlen(request->request_url));
            strcat(href_link, "/");
            strcat(href_link, name);
        } else {
            strncpy(href_link, name, strlen(name));
        }

        int len = snprintf(buf, SEND_BUFFER_SIZE,
                           "<tr><td><a href=\"%s\">%s</a></td></tr>\r\n",
                           href_link, name);
        if (len >= SEND_BUFFER_SIZE)  // avoid buffer not enough
            pr_err("Buffer truncated, required size: %d\n", len);

        http_server_send(request->socket, buf, strlen(buf));
    }
    return true;
}

static bool handle_directory(struct http_request *request, int keep_alive)
{
    struct file *fp;
    char pwd[BUFFER_SIZE] = {0};
    char buf[SEND_BUFFER_SIZE] = {0};
    char *connection = keep_alive ? "Keep-Alive" : "Close";

    request->dir_context.actor = tracedir;
    if (request->method != HTTP_GET) {
        SEND_HTTP_MSG(request->socket, buf, "%s%s%s%s%s%s",
                      "HTTP/1.1 501 Not Implemented\r\n",
                      "Content-Type: text/plain\r\n", "Content-Length: 19\r\n",
                      "Connection: ", connection,
                      "\r\n\r\n501 Not Implemented");
        return false;
    }

    // 串連 request_url 與 指定路徑
    catstr(pwd, daemon.root_path, request->request_url);

    // 開啟檔案
    fp = filp_open(pwd, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("Open file failed, fp : %ld\n", PTR_ERR(fp));
        return false;
    }

    // 判斷為目錄
    if (S_ISDIR(fp->f_inode->i_mode)) {
        // Send HTTP header
        SEND_HTTP_MSG(request->socket, buf, "%s%s%s%s%s", "HTTP/1.1 200 OK\r\n",
                      "Connection: ", connection,
                      "\r\nContent-Type: text/html\r\n",
                      "Keep-Alive: timeout=5, max=1000\r\n\r\n");

        // Send HTML header
        SEND_HTTP_MSG(
            request->socket, buf, "%s%s%s%s", "<html><head><style>\r\n",
            "body{font-family: monospace; font-size: 15px;}\r\n",
            "td {padding: 1.5px 6px;}\r\n", "</style></head><body><table>\r\n");

        // scan directory and send to client
        iterate_dir(fp, &request->dir_context);

        // Send HTML footer
        SEND_HTTP_MSG(request->socket, buf, "%s", "</table></body></html>\r\n");
    }
    // 判斷為檔案
    else if (S_ISREG(fp->f_inode->i_mode)) {
        char *read_data_buf = kmalloc(fp->f_inode->i_size, GFP_KERNEL);

        // 讀檔案內容
        int ret = kernel_read(fp, read_data_buf, fp->f_inode->i_size, 0);

        // Send HTTP header
        SEND_HTTP_MSG(request->socket, buf, "%s%s%s%s%d%s%s%s",
                      "HTTP/1.1 200 OK\r\n",
                      "Content-Type: ", get_mime_str(request->request_url),
                      "\r\nContent-Length: ", ret,
                      "\r\nConnection: ", connection, "\r\n\r\n");

        // Send file content
        http_server_send(request->socket, read_data_buf, ret);
        kfree(read_data_buf);
    }

    filp_close(fp, NULL);
    return true;
}

// static int http_server_worker(void *arg)
static void http_server_worker(struct work_struct *work)
{
    // get http_request from work
    struct http_request *http_work =
        container_of(work, struct http_request, khttpd_work);

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

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &http_work->socket;

    // add a timer to worker
    http_add_timer(http_work, TIMEOUT_DEFAULT, kernel_sock_shutdown);

    while (!daemon.is_stopped) {
        int ret =
            http_server_recv(http_work->socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        if (!http_parser_execute(&parser, &setting, buf, ret))
            continue;

        if (http_work->complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);

        http_timer_update(http_work->timer_node, TIMEOUT_DEFAULT);
    }
    kernel_sock_shutdown(http_work->socket, SHUT_RDWR);
    kfree(buf);
    // return 0;
}

static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work;

    // GFP_KERNEL: 正常配置記憶體
    if (!(work = kmalloc(sizeof(struct http_request), GFP_KERNEL)))
        return NULL;

    work->socket = sk;

    // 建立 work - http_server_worker function
    INIT_WORK(&work->khttpd_work, http_server_worker);
    list_add(&work->node, &daemon.worker);  // Add work to worker list

    return &work->khttpd_work;
}

static void free_work(void)
{
    struct http_request *tmp, *tgt;
    list_for_each_entry_safe (tgt, tmp, &daemon.worker, node) {
        kernel_sock_shutdown(tgt->socket, SHUT_RDWR);
        flush_work(&tgt->khttpd_work);
        sock_release(tgt->socket);
        kfree(tgt);
    }
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct http_server_param *param = (struct http_server_param *) arg;
    struct work_struct *work;

    // Init root path
    daemon.root_path = param->root_path;

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

    // initial timer to manage connect
    http_timer_init();

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, SOCK_NONBLOCK);

        // clean up expired timer
        handle_expired_timers();

        if (err < 0) {
            // 檢查此 thread 是否有 signal 發生
            if (signal_pending(current))
                break;
            // pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

        // create work
        work = create_work(socket);
        if (!work) {
            pr_err("can't create work\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
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
