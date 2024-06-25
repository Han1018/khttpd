#include "hash_content.h"

#define SEND_BUFFER_SIZE 256

DEFINE_HASHTABLE(ht, 8);
spinlock_t hash_lock;

void init_hash_table(void)
{
    hash_init(ht);
    spin_lock_init(&hash_lock);
}

void hash_insert(const char *request_url, struct list_head *head)
{
    // cal hash key
    u32 original_key = jhash(request_url, strlen(request_url), 0);
    u8 key = (u8) (original_key % 256);

    // init hash_content
    struct hash_content *content =
        kmalloc(sizeof(struct hash_content), GFP_KERNEL);
    content->head = head;
    content->request = kmalloc(strlen(request_url) + 1, GFP_KERNEL);
    memcpy(content->request, request_url, strlen(request_url) + 1);

    // add hash_content to the hash_table
    spin_lock(&hash_lock);
    struct hash_content *now = NULL;
    hash_for_each_possible_rcu(ht, now, node, key)
    {
        // 略過已經存在的 key
        char *now_request_url = now->request;
        if (strcmp(now_request_url, request_url) == 0) {
            pr_info("Key %s already exists in hash table\n", request_url);
            spin_unlock(&hash_lock);
            kfree(content->request);
            kfree(content);
            return;
        }
    }
    hash_add_rcu(ht, &content->node, key);
    spin_unlock(&hash_lock);

    // add a timer for hash_content
    int ret = http_add_timer(content, CACHE_TIME_OUT, remove_key_from_hashtable,
                             false);
    if (ret <= 0) {
        pr_err("Failed to add timer for key %s\n", request_url);
    }
    pr_info("Add key %s to hash table\n", request_url);
}

bool hash_check(const char *request, struct list_head **head)
{
    u32 original_key = jhash(request, strlen(request), 0);
    u8 key = (u8) (original_key % 256);
    struct hash_content *now = NULL;
    rcu_read_lock();
    hash_for_each_possible_rcu(ht, now, node, key)
    {
        if (strcmp(request, now->request) == 0) {
            *head = now->head;
            pr_info("Found key %s in hash table\n", request);
            // http_timer_update(now->timer_node, CACHE_TIME_OUT);
            pr_info("Update timer for key %s\n", request);
            rcu_read_unlock();
            return true;
        }
    }

    rcu_read_unlock();
    return false;
}

// 刪除指定 key 的元素
int remove_key_from_hashtable(void *hash_cnt)
{
    rcu_read_lock();  // 開始 RCU 讀取區段

    // 取得 request 字符串
    struct hash_content *content = (struct hash_content *) hash_cnt;
    char *request_url = content->request;

    pr_info("Prepare to remove key %s from hash table\n", request_url);

    struct hash_content *now = NULL;
    struct cache_content *cache_entry, *tmp;

    u32 original_key = jhash(request_url, strlen(request_url), 0);
    u8 key = (u8) (original_key % 256);

    hash_for_each_possible_rcu(ht, now, node, key)
    {
        char *now_request_url = now->request;
        if (strcmp(request_url, now_request_url) == 0) {
            pr_info("Removing key %s from hash table\n", request_url);

            // 刪除 hash_content from hash table
            spin_lock(&hash_lock);
            if (!hash_hashed(&now->node)) {  // 略過已經刪除的 (不應該發生)
                spin_unlock(&hash_lock);
                rcu_read_unlock();

                pr_info("Key already removed");
                return 0;
            }
            hash_del_rcu(&now->node);
            spin_unlock(&hash_lock);

            // 等待所有 RCU 讀取區段結束
            rcu_read_unlock();
            synchronize_rcu();

            // 釋放 cache list 的每一個 buffer
            list_for_each_entry_safe (cache_entry, tmp, now->head, cache) {
                list_del(&cache_entry->cache);
                kfree(cache_entry);
            }

            // release
            pr_info("Key removed");
            kfree(now->request);
            kfree(now);

            return 1;
        }
    }
    rcu_read_unlock();  // 結束 RCU 讀取區段
    return 0;
}

void hash_table_free(void)
{
    struct hash_content *entry = NULL;
    struct hlist_node *tmp = NULL;
    struct cache_content *now;
    struct cache_content *tag_temp;
    unsigned int bucket;

    hash_for_each_safe(ht, bucket, tmp, entry, node)
    {
        list_for_each_entry_safe (now, tag_temp, entry->head, cache) {
            list_del(&now->cache);
            kfree(now);
        }
        hash_del(&entry->node);
        kfree(entry);
    }
}