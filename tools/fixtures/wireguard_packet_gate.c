// Загрузчик для одноразового стенда. Ссылки и карты остаются в bpffs после выхода.
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

#include "wireguard_packet_gate.h"

_Static_assert(sizeof(struct yonik_wg_packet) == 80, "Размер ключа карты");

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

#define SELECTOR_FIELDS 5

static int freeze_selectors(struct bpf_object *object, int fields, char **entries)
{
    int endpoints = bpf_object__find_map_fd_by_name(object, "wg_endpoints");
    int sockets = bpf_object__find_map_fd_by_name(object, "wg_sockets");
    if (endpoints < 0 || sockets < 0)
        return 1;
    const __u32 present = 1;
    for (int i = 0; i < fields; i += SELECTOR_FIELDS) {
        struct yonik_wg_endpoint endpoint = {
            .family = !strcmp(entries[i], "4") ? AF_INET : !strcmp(entries[i], "6") ? AF_INET6 : 0,
            .source_port = htons(integer(entries[i + 2], 10, UINT16_MAX)),
            .destination_port = htons(integer(entries[i + 3], 10, UINT16_MAX)),
        };
        __u64 cookie = integer(entries[i + 4], 16, UINT64_MAX);
        if (!endpoint.family || inet_pton(endpoint.family, entries[i + 1], endpoint.destination) != 1)
            return 2;
        if (bpf_map_update_elem(endpoints, &endpoint, &present, BPF_ANY)
            || bpf_map_update_elem(sockets, &cookie, &present, BPF_ANY))
            return 1;
    }
    return bpf_map_freeze(endpoints) || bpf_map_freeze(sockets);
}

static int load(int argc, char **argv)
{
    const int guarded = !strcmp(argv[1], "load-guarded");
    const int late = guarded || !strcmp(argv[1], "load-late");
    const int fields = argc - 4;
    if ((guarded && (fields < SELECTOR_FIELDS || fields % SELECTOR_FIELDS
                    || fields / SELECTOR_FIELDS > YONIK_WG_MAX_LEASES))
        || (!guarded && argc != 5))
        return 2;
    const char *file = argv[2];
    const char *dir = argv[3];
    const __u32 mark = guarded ? 0 : integer(argv[4], 10, UINT32_MAX);
    struct bpf_object *object = bpf_object__open_file(file, NULL);
    if (!object || bpf_object__load(object))
        return 1;
    struct bpf_program *program = bpf_object__find_program_by_name(object, "wireguard_gate");
    __u32 zero = 0;
    int fd = bpf_object__find_map_fd_by_name(object, "wg_mark");
    if (!program || fd < 0 || bpf_map_update_elem(fd, &zero, &mark, BPF_ANY))
        return 1;
    int result = freeze_selectors(object, guarded ? fields : 0, argv + 4);
    if (result)
        return result;

    const char *names[] = {"wg_leases", "wg_verdicts", "wg_active", "v4", "v6", "post4", "post6"};
    char path[256];
    struct bpf_link *links[4] = {};
    const unsigned int families[] = { NFPROTO_IPV4, NFPROTO_IPV6 };
    const int map_count = 3;
    const int link_count = guarded ? 4 : 2;
    const int pin_count = map_count + link_count;
    int installed = 0;
    for (; installed < pin_count; installed++) {
        pin_name(path, dir, names[installed]);
        if (installed < map_count) {
            fd = bpf_object__find_map_fd_by_name(object, names[installed]);
            if (fd < 0 || bpf_obj_pin(fd, path))
                break;
        } else {
            int link = installed - map_count;
            // POST_ROUTING проверяет уже итог OUTPUT до штатного SNAT.
            int postrouting = link >= 2;
            struct bpf_netfilter_opts opts = {
                .sz = sizeof(opts), .pf = families[link % 2],
                .hooknum = postrouting ? NF_INET_POST_ROUTING : NF_INET_LOCAL_OUT,
                .priority = postrouting ? NF_IP_PRI_NAT_SRC - 1 : late ? INT_MAX - 1 : -150,
            };
            links[link] = bpf_program__attach_netfilter(program, &opts);
            if (!links[link] || bpf_link__pin(links[link], path))
                break;
        }
    }
    result = installed != pin_count;
    if (result) {
        perror("Закрепление BPF");
        for (int i = installed - 1; i >= 0; i--) {
            pin_name(path, dir, names[i]);
            unlink(path);
        }
    }
    for (int i = link_count - 1; i >= 0; i--)
        bpf_link__destroy(links[i]);
    bpf_object__close(object);
    return result;
}

static int lock_gate(const char *dir)
{
    int lock = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (lock < 0 || flock(lock, LOCK_EX)) {
        perror("Блокировка каталога BPF");
        exit(1);
    }
    return lock;
}

static int read_session(int fd, struct yonik_wg_session *session)
{
    const __u32 zero = 0;
    return bpf_map_lookup_elem_flags(fd, &zero, session, BPF_F_LOCK);
}

static int require_revision(int fd, __u64 generation, __u64 revision,
                            struct yonik_wg_session *session)
{
    if (read_session(fd, session))
        return 1;
    return session->active && generation == session->generation
        && revision == session->revision ? 0 : 3;
}

static int reserve_revision(int fd, struct yonik_wg_session *session)
{
    const __u32 zero = 0;
    if (session->revision == UINT64_MAX)
        return 1;
    // Сначала закрываем предыдущую ревизию для издателей. Если подмена
    // карты не удастся, старая карта сохранит только исходный TTL.
    session->revision++;
    return bpf_map_update_elem(fd, &zero, session, BPF_F_LOCK | BPF_EXIST) != 0;
}

static int lookup_snapshot(int outer, __u32 *id)
{
    const __u32 zero = 0;
    if (!bpf_map_lookup_elem(outer, &zero, id))
        return 0;
    if (errno != ENOENT)
        return 1;
    *id = 0;
    return 0;
}

static int remove_snapshot(int outer)
{
    const __u32 zero = 0;
    return bpf_map_delete_elem(outer, &zero) && errno != ENOENT;
}

static int change_session(const char *dir, __u64 generation, bool start)
{
    int lock = lock_gate(dir);
    int fd = open_map(dir, "wg_active");
    int outer = open_map(dir, "wg_leases");
    const __u32 zero = 0;
    struct yonik_wg_session session = {};
    int result = 1;
    if (read_session(fd, &session))
        goto done;
    if (start ? (session.active || generation <= session.generation)
              : (!session.active || generation != session.generation)) {
        result = 3;
        goto done;
    }
    // Start начинается с пустого снимка. Stop прежде всего закрывает допуск.
    if (start && remove_snapshot(outer))
        goto done;
    session.generation = generation;
    session.active = start;
    if (start)
        session.revision = 1;
    result = bpf_map_update_elem(fd, &zero, &session, BPF_F_LOCK | BPF_EXIST) != 0;
    if (!start && !result)
        result = remove_snapshot(outer);
done:
    close(outer);
    close(fd);
    close(lock);
    return result;
}

// Поля одной записи одинаковы у allow/revoke и у публикации снимка.
static struct yonik_wg_packet parse_packet(char **fields, __u64 generation)
{
    struct yonik_wg_packet packet = {
        .cookie = integer(fields[7], 16, UINT64_MAX),
        .mark = integer(fields[6], 10, UINT32_MAX),
        .ifindex = integer(fields[5], 10, UINT32_MAX),
        .source_port = htons(integer(fields[3], 10, UINT16_MAX)),
        .destination_port = htons(integer(fields[4], 10, UINT16_MAX)),
        .generation = generation,
    };
    if (!strcmp(fields[0], "4"))
        packet.family = AF_INET;
    else if (!strcmp(fields[0], "6"))
        packet.family = AF_INET6;
    else
        exit(2);
    if (inet_pton(packet.family, fields[1], packet.source) != 1
        || inet_pton(packet.family, fields[2], packet.destination) != 1)
        exit(2);
    if (!strcmp(fields[8], "-"))
        memcpy(packet.next_hop, packet.destination, sizeof(packet.next_hop));
    else if (inet_pton(packet.family, fields[8], packet.next_hop) != 1)
        exit(2);
    return packet;
}

static __u64 boottime(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now))
        exit(1);
    return (__u64)now.tv_sec * 1000000000 + now.tv_nsec;
}

static __u64 deadline(__u64 now, const char *ttl_ms)
{
    __u64 duration = integer(ttl_ms, 10, 60000) * 1000000;
    if (now > UINT64_MAX - duration)
        exit(2);
    return now + duration;
}

static int create_snapshot(void)
{
    const struct bpf_map_create_opts opts = {
        .sz = sizeof(opts),
        .map_flags = YONIK_WG_LEASE_FLAGS,
    };
    return bpf_map_create(BPF_MAP_TYPE_HASH, "yonik_wg_routes", sizeof(struct yonik_wg_packet),
                          sizeof(__u64), YONIK_WG_MAX_LEASES, &opts);
}

static int install_snapshot(int outer, int inner)
{
    const __u32 zero = 0;
    return bpf_map_update_elem(outer, &zero, &inner, BPF_ANY) != 0;
}

static int publish_snapshot(const char *dir, __u64 generation, __u64 revision,
                            int inner, __u64 earliest_expiry)
{
    // Сеанс мог завершиться за время сборки и заморозки карты.
    int lock = lock_gate(dir);
    int session_fd = open_map(dir, "wg_active");
    struct yonik_wg_session session;
    int result = require_revision(session_fd, generation, revision, &session);
    if (!result && inner >= 0 && earliest_expiry <= boottime())
        result = 3;
    if (!result) {
        int outer = open_map(dir, "wg_leases");
        result = reserve_revision(session_fd, &session)
            || (inner < 0 ? remove_snapshot(outer) : install_snapshot(outer, inner));
        close(outer);
    }
    close(session_fd);
    close(lock);
    return result;
}

static int replace_snapshot(int argc, char **argv)
{
    const int fields_per_lease = 10;
    if (argc < 5 || (argc - 5) % fields_per_lease
        || (argc - 5) / fields_per_lease > YONIK_WG_MAX_LEASES)
        return 2;
    const char *dir = argv[2];
    __u64 generation = integer(argv[3], 10, UINT64_MAX);
    __u64 revision = integer(argv[4], 10, UINT64_MAX);
    int inner = -1;
    if (argc > 5) {
        inner = create_snapshot();
        if (inner < 0)
            return 1;
        __u64 now = boottime();
        for (int i = 5; i < argc; i += fields_per_lease) {
            struct yonik_wg_packet packet = parse_packet(argv + i, generation);
            __u64 expires = deadline(now, argv[i + 9]);
            if (bpf_map_update_elem(inner, &packet, &expires, BPF_NOEXIST))
                return 1;
        }
        if (bpf_map_freeze(inner))
            return 1;
    }

    int result = publish_snapshot(dir, generation, revision, inner, UINT64_MAX);
    if (inner >= 0)
        close(inner);
    return result;
}

static int replace_snapshot_binary(const char *dir, __u64 generation, __u64 revision)
{
    struct {
        struct yonik_wg_packet packet;
        __u64 expires;
    } record;
    _Static_assert(sizeof(record) == 88, "Размер записи допуска");
    const __u64 max_validity_ns = 2000000000; // Срок снимка маршрута в Rust.
    __u64 earliest_expiry = UINT64_MAX;
    int inner = -1;
    int result = 2;
    size_t count = 0;
    size_t size;
    while ((size = fread(&record, 1, sizeof(record), stdin)) != 0) {
        const struct yonik_wg_packet *packet = &record.packet;
        const __u64 now = boottime();
        if (size != sizeof(record) || count == YONIK_WG_MAX_LEASES
            || packet->generation != generation || !packet->cookie || !packet->mark
            || !packet->ifindex || !packet->source_port || !packet->destination_port
            || (packet->family != AF_INET && packet->family != AF_INET6)
            || record.expires <= now || record.expires - now > max_validity_ns)
            goto done;
        if (count++ == 0)
            inner = create_snapshot();
        if (inner < 0 || bpf_map_update_elem(inner, packet, &record.expires, BPF_NOEXIST)) {
            result = 1;
            goto done;
        }
        if (record.expires < earliest_expiry)
            earliest_expiry = record.expires;
    }
    if (ferror(stdin))
        goto done;
    if (inner >= 0 && bpf_map_freeze(inner)) {
        result = 1;
        goto done;
    }
    result = publish_snapshot(dir, generation, revision, inner, earliest_expiry);
done:
    if (inner >= 0)
        close(inner);
    return result;
}

static int copy_survivors(int from, int to, const struct yonik_wg_packet *excluded, __u64 now)
{
    struct yonik_wg_packet key, previous;
    const struct yonik_wg_packet *cursor = NULL;
    while (!bpf_map_get_next_key(from, cursor, &key)) {
        __u64 expires;
        if (bpf_map_lookup_elem(from, &key, &expires))
            return 1;
        if (expires > now && memcmp(&key, excluded, sizeof(key))
            && bpf_map_update_elem(to, &key, &expires, BPF_NOEXIST))
            return 1;
        previous = key;
        cursor = &previous;
    }
    return errno != ENOENT;
}

static int change_lease(int argc, char **argv)
{
    bool remove = !strcmp(argv[1], "revoke");
    if (argc != (remove ? 14 : 15))
        return 2;
    const char *dir = argv[2];
    __u64 generation = integer(argv[12], 10, UINT64_MAX);
    __u64 revision = integer(argv[13], 10, UINT64_MAX);
    struct yonik_wg_packet packet = parse_packet(argv + 3, generation);
    int lock = lock_gate(dir);
    int session_fd = open_map(dir, "wg_active");
    struct yonik_wg_session session;
    int result = require_revision(session_fd, generation, revision, &session);
    if (result) {
        close(session_fd);
        close(lock);
        return result;
    }
    int outer = open_map(dir, "wg_leases");
    __u32 id;
    if (lookup_snapshot(outer, &id) || (remove && !id))
        return 1;
    __u64 now = boottime();
    int inner = create_snapshot();
    if (inner < 0)
        return 1;
    if (id) {
        int old = bpf_map_get_fd_by_id(id);
        __u64 ignored;
        if (old < 0 || (remove && bpf_map_lookup_elem(old, &packet, &ignored))
            || copy_survivors(old, inner, &packet, now))
            return 1;
        close(old);
    }
    if (!remove) {
        __u64 expires = deadline(now, argv[14]);
        if (bpf_map_update_elem(inner, &packet, &expires, BPF_NOEXIST))
            return 1;
    }
    result = bpf_map_freeze(inner) != 0 || reserve_revision(session_fd, &session)
        || install_snapshot(outer, inner);
    close(inner);
    close(outer);
    close(session_fd);
    close(lock);
    return result;
}

int main(int argc, char **argv)
{
    if (argc > 1 && (!strcmp(argv[1], "load") || !strcmp(argv[1], "load-late")
                     || !strcmp(argv[1], "load-guarded")))
        return load(argc, argv);
    if (argc == 4 && (!strcmp(argv[1], "start") || !strcmp(argv[1], "stop")))
        return change_session(argv[2], integer(argv[3], 10, UINT64_MAX), !strcmp(argv[1], "start"));
    if (argc > 1 && !strcmp(argv[1], "replace"))
        return replace_snapshot(argc, argv);
    if (argc == 5 && !strcmp(argv[1], "replace-binary"))
        return replace_snapshot_binary(argv[2], integer(argv[3], 10, UINT64_MAX),
                                       integer(argv[4], 10, UINT64_MAX));
    if (argc == 3 && !strcmp(argv[1], "revision")) {
        int lock = lock_gate(argv[2]);
        int fd = open_map(argv[2], "wg_active");
        struct yonik_wg_session session;
        int result = read_session(fd, &session);
        close(fd);
        close(lock);
        if (result)
            return 1;
        printf("%" PRIu64 "\n", (uint64_t)session.revision);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "snapshot")) {
        int outer = open_map(argv[2], "wg_leases");
        __u32 id;
        if (lookup_snapshot(outer, &id))
            return 1;
        printf("%u\n", id);
        return 0;
    }
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
