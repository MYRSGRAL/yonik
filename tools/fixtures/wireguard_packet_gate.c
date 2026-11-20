// Загрузчик для одноразового стенда. Ссылки и карты остаются в bpffs после выхода.
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/netfilter.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "wireguard_packet_gate.h"

_Static_assert(sizeof(struct yonik_wg_packet) == 56, "Размер ключа карты");

static uint64_t integer(const char *text, unsigned int radix, uint64_t limit)
{
    char *end;
    errno = 0;
    uint64_t value = strtoull(text, &end, radix);
    if (*text == '-' || end == text || *end || errno || !value || value > limit)
        exit(2);
    return value;
}

static void pin_name(char path[256], const char *dir, const char *name)
{
    if (snprintf(path, 256, "%s/%s", dir, name) >= 256)
        exit(2);
}

static int open_map(const char *dir, const char *name)
{
    char path[256];
    pin_name(path, dir, name);
    int fd = bpf_obj_get(path);
    if (fd < 0) {
        perror(path);
        exit(1);
    }
    return fd;
}

static int load(const char *file, const char *dir, __u32 mark)
{
    struct bpf_object *object = bpf_object__open_file(file, NULL);
    if (!object || bpf_object__load(object))
        return 1;
    struct bpf_program *program = bpf_object__find_program_by_name(object, "wireguard_gate");
    __u32 zero = 0;
    int fd = bpf_object__find_map_fd_by_name(object, "wg_mark");
    if (!program || fd < 0 || bpf_map_update_elem(fd, &zero, &mark, BPF_ANY))
        return 1;

    const char *names[] = {"wg_leases", "wg_verdicts", "v4", "v6"};
    char path[256];
    struct bpf_link *links[2] = {};
    const unsigned int families[] = { NFPROTO_IPV4, NFPROTO_IPV6 };
    int installed = 0;
    for (; installed < 4; installed++) {
        pin_name(path, dir, names[installed]);
        if (installed < 2) {
            fd = bpf_object__find_map_fd_by_name(object, names[installed]);
            if (fd < 0 || bpf_obj_pin(fd, path))
                break;
        } else {
            struct bpf_netfilter_opts opts = {
                .sz = sizeof(opts), .pf = families[installed - 2],
                .hooknum = NF_INET_LOCAL_OUT, .priority = -150,
            };
            links[installed - 2] = bpf_program__attach_netfilter(program, &opts);
            if (!links[installed - 2] || bpf_link__pin(links[installed - 2], path))
                break;
        }
    }
    int result = installed != 4;
    if (result) {
        perror("Закрепление BPF");
        for (int i = installed - 1; i >= 0; i--) {
            pin_name(path, dir, names[i]);
            unlink(path);
        }
    }
    bpf_link__destroy(links[1]);
    bpf_link__destroy(links[0]);
    bpf_object__close(object);
    return result;
}

static int change_lease(int argc, char **argv)
{
    bool remove = !strcmp(argv[1], "revoke");
    if (argc != (remove ? 11 : 12))
        return 2;
    struct yonik_wg_packet packet = {
        .cookie = integer(argv[10], 16, UINT64_MAX),
        .mark = integer(argv[9], 10, UINT32_MAX),
        .ifindex = integer(argv[8], 10, UINT32_MAX),
        .source_port = htons(integer(argv[6], 10, UINT16_MAX)),
        .destination_port = htons(integer(argv[7], 10, UINT16_MAX)),
    };
    if (!strcmp(argv[3], "4"))
        packet.family = AF_INET;
    else if (!strcmp(argv[3], "6"))
        packet.family = AF_INET6;
    else
        return 2;
    if (inet_pton(packet.family, argv[4], packet.source) != 1
        || inet_pton(packet.family, argv[5], packet.destination) != 1)
        return 2;

    int fd = open_map(argv[2], "wg_leases");
    if (remove)
        return bpf_map_delete_elem(fd, &packet) != 0;
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now))
        return 1;
    __u64 expires = (__u64)now.tv_sec * 1000000000 + now.tv_nsec;
    expires += integer(argv[11], 10, 60000) * 1000000;
    return bpf_map_update_elem(fd, &packet, &expires, BPF_ANY) != 0;
}

int main(int argc, char **argv)
{
    if (argc == 5 && !strcmp(argv[1], "load"))
        return load(argv[2], argv[3], integer(argv[4], 10, UINT32_MAX));
    if (argc == 3 && !strcmp(argv[1], "counters")) {
        int fd = open_map(argv[2], "wg_verdicts");
        for (__u32 verdict = 0; verdict < YONIK_WG_VERDICTS; verdict++) {
            uint64_t count;
            if (bpf_map_lookup_elem(fd, &verdict, &count))
                return 1;
            printf("%" PRIu64 "%c", count, verdict + 1 == YONIK_WG_VERDICTS ? '\n' : ' ');
        }
        return 0;
    }
    if (argc > 1 && (!strcmp(argv[1], "allow") || !strcmp(argv[1], "revoke")))
        return change_lease(argc, argv);
    return 2;
}
