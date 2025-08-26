#ifndef DNS_DUMMY_SERVER_H
#define DNS_DUMMY_SERVER_H

#include <stdint.h>
#include <stddef.h>

#define DEFAULT_DNS_PORT 53
#define MAX_DNS_RR_SIZE 512
#define MAX_NAME_LEN 128
#define MAX_CHAIN_LEN 10
#define MAX_A_RRS 10
#define MAX_PKT_SIZE 1500
#define MAX_COMPRESSED_NAMES 64

typedef struct {
    char name_txt[MAX_NAME_LEN];
    uint16_t type;
    uint32_t ttl;
    char target_txt[MAX_NAME_LEN];
    uint8_t name[MAX_NAME_LEN];
    size_t name_len;
    uint8_t target[MAX_NAME_LEN];
    size_t target_len;
    uint8_t rdata[16];
    size_t rdata_len;
} DNSRecord;

typedef struct {
    uint8_t name[MAX_NAME_LEN];
    size_t name_len;
    size_t offset; // offset in resp
} NameOffset;

void *stat_thread(void *arg);

size_t random_dns_name(uint8_t *buf, size_t maxlen, char *out_txt);

void random_ipv4(uint8_t *buf);

int generate_dns_chain(DNSRecord *records, int max_records, const uint8_t *qname, size_t qname_len);

size_t copy_question(const uint8_t *query, uint8_t *resp, size_t offset);

ssize_t find_name(NameOffset *arr, int count, const uint8_t *name, size_t name_len);
void add_name(NameOffset *arr, int *count, const uint8_t *name, size_t name_len, size_t offset);

size_t put_name(uint8_t *resp, size_t resp_max, size_t pos, const uint8_t *name, size_t name_len,
                NameOffset *names, int *names_count);

#endif // DNS_DUMMY_SERVER_H
