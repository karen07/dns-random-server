#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <pthread.h>
#include "dns_dummy_server.h"

static volatile unsigned long req_count = 0;
static int run_stats = 1;

void *stat_thread(void *arg)
{
    (void)arg;
    unsigned long last = 0;
    while (run_stats) {
        sleep(1);
        unsigned long cnt = req_count;
        printf("Received DNS requests: %lu (+%lu)\n", cnt, cnt - last);
        last = cnt;
    }
    return NULL;
}

size_t random_dns_name(uint8_t *buf, size_t maxlen, char *out_txt)
{
    const char *labels[] = {
        "www",    "mail",   "ns",      "ftp",     "api",     "test",    "cdn",    "srv",
        "edge",   "node",   "admin",   "office",  "dev",     "prod",    "lab",    "proxy",
        "gw",     "backup", "home",    "vpn",     "user",    "files",   "db",     "sql",
        "web",    "cloud",  "app",     "crm",     "billing", "cache",   "shop",   "store",
        "search", "help",   "wiki",    "docs",    "img",     "static",  "ad",     "log",
        "pki",    "qa",     "beta",    "rc",      "alpha",   "monitor", "alert",  "ntp",
        "git",    "svn",    "gitlab",  "grafana", "stats",   "jira",    "bug",    "report",
        "ci",     "cd",     "docker",  "k8s",     "api2",    "api3",    "api4",   "old",
        "new",    "gw2",    "gw3",     "router",  "sip",     "voip",    "sms",    "mms",
        "wap",    "stream", "cam",     "printer", "room",    "iot",     "devops", "ops",
        "vault",  "secret", "hub",     "core",    "dmz",     "edge2",   "tor",    "cdn2",
        "mx",     "mail2",  "imap",    "pop",     "smtp",    "news",    "blog",   "forum",
        "chat",   "irc",    "discord", "guest"
    };
    int n_labels = sizeof(labels) / sizeof(labels[0]);
    const char *zones[] = { "com", "net", "org", "ru", "info" };
    int n_zones = sizeof(zones) / sizeof(zones[0]);

    size_t pos = 0, o = 0;
    int parts = 2 + rand() % 2;
    for (int i = 0; i < parts; ++i) {
        const char *label = labels[rand() % n_labels];
        size_t len = strlen(label);
        if (pos + len + 2 >= maxlen)
            break;
        buf[pos++] = len;
        memcpy(buf + pos, label, len);
        pos += len;
        if (out_txt) {
            if (o > 0)
                out_txt[o++] = '.';
            memcpy(out_txt + o, label, len);
            o += len;
        }
    }
    const char *zone = zones[rand() % n_zones];
    size_t len = strlen(zone);
    if (pos + len + 2 < maxlen) {
        buf[pos++] = len;
        memcpy(buf + pos, zone, len);
        pos += len;
        if (out_txt) {
            out_txt[o++] = '.';
            memcpy(out_txt + o, zone, len);
            o += len;
        }
    }
    buf[pos++] = 0;
    if (out_txt)
        out_txt[o] = 0;
    return pos;
}

void random_ipv4(uint8_t *buf)
{
    for (int i = 0; i < 4; i++)
        buf[i] = rand() % 256;
}

int generate_dns_chain(DNSRecord *records, int max_records, const uint8_t *qname, size_t qname_len)
{
    uint8_t names[MAX_CHAIN_LEN + 1][MAX_NAME_LEN];
    char names_txt[MAX_CHAIN_LEN + 1][MAX_NAME_LEN];
    size_t names_lens[MAX_CHAIN_LEN + 1];

    int chain_len = 1 + rand() % MAX_CHAIN_LEN;
    int a_count = 1 + rand() % MAX_A_RRS;

    if (chain_len + a_count > max_records)
        a_count = max_records - chain_len;
    if (a_count < 1)
        a_count = 1;

    int total_rrs = chain_len + a_count;

    memcpy(names[0], qname, qname_len);
    names_lens[0] = qname_len;
    names_txt[0][0] = 0;

    for (int i = 1; i < chain_len + 1; ++i) {
        names_lens[i] = random_dns_name(names[i], MAX_NAME_LEN, names_txt[i]);
    }

    for (int i = 0; i < chain_len; ++i) {
        DNSRecord *rec_c = &records[i];
        memcpy(rec_c->name, names[i], names_lens[i]);
        rec_c->name_len = names_lens[i];
        snprintf(rec_c->name_txt, MAX_NAME_LEN, "%.*s", MAX_NAME_LEN - 1, names_txt[i]);
        rec_c->type = 5;
        rec_c->ttl = 30 + rand() % 1000;
        memcpy(rec_c->target, names[i + 1], names_lens[i + 1]);
        rec_c->target_len = names_lens[i + 1];
        snprintf(rec_c->target_txt, MAX_NAME_LEN, "%.*s", MAX_NAME_LEN - 1, names_txt[i + 1]);
        memcpy(rec_c->rdata, names[i + 1], names_lens[i + 1]);
        rec_c->rdata_len = names_lens[i + 1];
    }

    int idx = chain_len;
    for (int i = 0; i < a_count; ++i) {
        DNSRecord *rec_a = &records[idx + i];
        memcpy(rec_a->name, names[chain_len], names_lens[chain_len]);
        rec_a->name_len = names_lens[chain_len];
        snprintf(rec_a->name_txt, MAX_NAME_LEN, "%.*s", MAX_NAME_LEN - 1, names_txt[chain_len]);
        rec_a->type = 1;
        rec_a->ttl = 30 + rand() % 1000;
        uint8_t ip[4];
        random_ipv4(ip);
        snprintf(rec_a->target_txt, MAX_NAME_LEN, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
        memcpy(rec_a->rdata, ip, 4);
        rec_a->rdata_len = 4;
    }
    return total_rrs;
}

size_t copy_question(const uint8_t *query, uint8_t *resp, size_t offset)
{
    size_t qname_len = 0;
    while (query[qname_len])
        qname_len++;
    qname_len++;
    memcpy(resp + offset, query, qname_len + 4);
    return qname_len + 4;
}

ssize_t find_name(NameOffset *arr, int count, const uint8_t *name, size_t name_len)
{
    for (int i = 0; i < count; ++i) {
        if (arr[i].name_len == name_len && memcmp(arr[i].name, name, name_len) == 0)
            return arr[i].offset;
    }
    return -1;
}
void add_name(NameOffset *arr, int *count, const uint8_t *name, size_t name_len, size_t offset)
{
    if (*count >= MAX_COMPRESSED_NAMES)
        return;
    arr[*count].name_len = name_len;
    memcpy(arr[*count].name, name, name_len);
    arr[*count].offset = offset;
    (*count)++;
}

size_t put_name(uint8_t *resp, size_t resp_max, size_t pos, const uint8_t *name, size_t name_len,
                NameOffset *names, int *names_count)
{
    ssize_t ptr = find_name(names, *names_count, name, name_len);
    if (ptr >= 0) {
        if (pos + 2 > resp_max)
            return 0;
        resp[pos++] = 0xC0 | ((ptr >> 8) & 0x3F);
        resp[pos++] = ptr & 0xFF;
        return 2;
    } else {
        if (pos + name_len > resp_max)
            return 0;
        memcpy(resp + pos, name, name_len);
        add_name(names, names_count, name, name_len, pos);
        return name_len;
    }
}

void print_help(void)
{
    printf("Commands:\n"
           "  Required parameters:\n"
           "    -l  \"x.x.x.x:xx\"  Listen address\n");
}

int main(int argc, char **argv)
{
    srand((unsigned)time(NULL));

    const char *listen_ip = "0.0.0.0";
    int port = DEFAULT_DNS_PORT;

    if (argc < 3 || strcmp(argv[1], "-l") != 0) {
        print_help();
        return 1;
    }

    pthread_t stat_tid;
    if (pthread_create(&stat_tid, NULL, stat_thread, NULL) != 0) {
        fprintf(stderr, "Cannot create stat thread\n");
        return 1;
    }

    char ipbuf[64] = { 0 };
    char *colon = strchr(argv[2], ':');
    if (!colon) {
        print_help();
        return 1;
    }
    size_t iplen = colon - argv[2];
    if (iplen >= sizeof(ipbuf))
        iplen = sizeof(ipbuf) - 1;
    strncpy(ipbuf, argv[2], iplen);
    ipbuf[iplen] = 0;
    listen_ip = ipbuf;
    port = atoi(colon + 1);
    if (port < 1 || port > 65535) {
        fprintf(stderr, "Invalid port: %d\n", port);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_aton(listen_ip, &addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", listen_ip);
        return 1;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    printf("DNS dummy-server started on %s:%d\n", listen_ip, port);

    while (1) {
        uint8_t buf[MAX_PKT_SIZE];
        struct sockaddr_in cli;
        socklen_t slen = sizeof(cli);

        ssize_t rlen = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&cli, &slen);
        if (rlen < 0) {
            perror("recvfrom");
            continue;
        }
        if (rlen < 12)
            continue;

        req_count++;

        uint16_t qdcount = (buf[4] << 8) | buf[5];
        if (qdcount == 0)
            continue;

        size_t offset = 12;
        size_t qname_len = 0;
        while (offset + qname_len < (size_t)rlen && buf[offset + qname_len])
            qname_len++;
        if (offset + qname_len >= (size_t)rlen)
            continue;
        qname_len++;

        uint8_t resp[MAX_PKT_SIZE];
        memset(resp, 0, sizeof(resp));
        memcpy(resp, buf, 2);
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[4] = 0x00;
        resp[5] = 0x01;
        resp[8] = 0x00;
        resp[9] = 0x00;
        resp[10] = 0x00;
        resp[11] = 0x00;

        size_t resp_len = 12;
        size_t quest_len = copy_question(buf + offset, resp, resp_len);
        resp_len += quest_len;

        DNSRecord records[MAX_CHAIN_LEN + MAX_A_RRS];
        int n = generate_dns_chain(records, MAX_CHAIN_LEN + MAX_A_RRS, buf + offset, qname_len);

        NameOffset names_seen[MAX_COMPRESSED_NAMES];
        int names_seen_count = 0;
        add_name(names_seen, &names_seen_count, buf + offset, qname_len, 12);

        for (int i = 0; i < n; ++i) {
            size_t owner_len = put_name(resp, MAX_PKT_SIZE, resp_len, records[i].name,
                                        records[i].name_len, names_seen, &names_seen_count);
            resp_len += owner_len;
            if (resp_len + 10 > MAX_PKT_SIZE)
                break;
            resp[resp_len++] = records[i].type >> 8;
            resp[resp_len++] = records[i].type & 0xFF;
            resp[resp_len++] = 0;
            resp[resp_len++] = 1;
            resp[resp_len++] = (records[i].ttl >> 24) & 0xFF;
            resp[resp_len++] = (records[i].ttl >> 16) & 0xFF;
            resp[resp_len++] = (records[i].ttl >> 8) & 0xFF;
            resp[resp_len++] = records[i].ttl & 0xFF;
            size_t rdata_len_pos = resp_len;
            resp_len += 2;
            size_t rdata_len = 0;
            if (records[i].type == 5) {
                rdata_len = put_name(resp, MAX_PKT_SIZE, resp_len, records[i].target,
                                     records[i].target_len, names_seen, &names_seen_count);
                resp_len += rdata_len;
            } else if (records[i].type == 1) {
                if (resp_len + 4 > MAX_PKT_SIZE)
                    break;
                memcpy(resp + resp_len, records[i].rdata, 4);
                rdata_len = 4;
                resp_len += 4;
            }
            resp[rdata_len_pos] = (rdata_len >> 8) & 0xFF;
            resp[rdata_len_pos + 1] = rdata_len & 0xFF;
        }

        resp[6] = ((n >> 8) & 0xFF);
        resp[7] = (n & 0xFF);

        sendto(sock, resp, resp_len, 0, (struct sockaddr *)&cli, slen);
    }

    run_stats = 0;
    pthread_join(stat_tid, NULL);
    return 0;
}
