#ifndef HASH_CONTENT_H
#define HASH_CONTENT_H

#include <linux/gfp.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "http_server.h"
#include "timer.h"

#define CACHE_TIME_OUT 2000

struct hash_content {
    struct list_head *head;
    char *request;
    struct hlist_node node;
    void *timer_node;
};

void init_hash_table(void);

void hash_insert(const char *request, struct list_head *head);

bool hash_check(const char *request, struct list_head **head);

void hash_table_free(void);

int remove_key_from_hashtable(void *hash_cnt);

#endif