#ifndef TCP_INFO_HELPERS_H
#define TCP_INFO_HELPERS_H

#include "vmlinux.h"
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "http_defs.h"
#include "sec.h"
#include "bpf_endian.h"

const u8 ip4ip6_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// Taken from uapi/linux/tcp.h
struct __tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

typedef struct protocol_info {
    u32 hdr_len;
    u32 seq;
    u8  flags;
    u8  type;
} protocol_info_t;


typedef struct sock_args {
    u64 addr; // linux sock or socket address
} sock_args_t;

static __always_inline bool parse_sock_info(struct sock *s, connection_info_t *info) {
    short unsigned int skc_family;
    BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
    
    // We always store the IP addresses in IPV6 format, simplifies the code and
    // it matches natively what our Golang userspace processing will require.
    if (skc_family == AF_INET) {
        u32 ip4_s_l;
        u32 ip4_d_l;
        BPF_CORE_READ_INTO(&info->s_port, s, __sk_common.skc_num); // weirdly not in network byte order
        BPF_CORE_READ_INTO(&ip4_s_l, s, __sk_common.skc_rcv_saddr);        
        BPF_CORE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_CORE_READ_INTO(&ip4_d_l, s, __sk_common.skc_daddr);

        __builtin_memcpy(info->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(info->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(info->s_addr + sizeof(ip4ip6_prefix), &ip4_s_l, sizeof(ip4_s_l));
        __builtin_memcpy(info->d_addr + sizeof(ip4ip6_prefix), &ip4_d_l, sizeof(ip4_d_l));

        return true;
    } else if (skc_family == AF_INET6) {
        BPF_CORE_READ_INTO(&info->s_port, s, __sk_common.skc_num); // weirdly not in network byte order
        BPF_CORE_READ_INTO(&info->s_addr, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_CORE_READ_INTO(&info->d_addr, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

        return true;
    }

    return false;
}

// We tag the server and client calls in flags to avoid mistaking a mutual connection between two
// services as the same connection info. It would be almost impossible, but it might happen.
static __always_inline bool parse_accept_socket_info(sock_args_t *args, connection_info_t *info) {
    struct sock *s;

    struct socket *sock = (struct socket*)(args->addr);
    BPF_CORE_READ_INTO(&s, sock, sk);

    return parse_sock_info(s, info);
}

static __always_inline bool parse_connect_sock_info(sock_args_t *args, connection_info_t *info) {
    return parse_sock_info((struct sock*)(args->addr), info);
}


static __always_inline bool read_sk_buff(struct __sk_buff *skb, protocol_info_t *tcp, connection_info_t *conn) {
    // we read the protocol just like here linux/samples/bpf/parse_ldabs.c
    u16 h_proto;
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto));
    h_proto = __bpf_htons(h_proto);

    u8 proto = 0;
    // do something similar as linux/samples/bpf/parse_varlen.c
    switch (h_proto) {
    case ETH_P_IP: {
        u8 hdr_len;
        // ip4 header lengths are variable
        // access ihl as a u8 (linux/include/linux/skbuff.h)
        bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
        hdr_len &= 0x0f;
        hdr_len *= 4;

        /* verify hlen meets minimum size requirements */
        if (hdr_len < sizeof(struct iphdr)) {
            return false;
        }

        // we read the ip header linux/samples/bpf/parse_ldabs.c and linux/samples/bpf/tcbpf1_kern.c
        // the level 4 protocol let's us only filter TCP packets, the ip protocol gets us the source
        // and destination IP pairs
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &proto, sizeof(proto));

        u32 saddr;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &saddr, sizeof(saddr));
        u32 daddr;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &daddr, sizeof(daddr));

        __builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(conn->s_addr + sizeof(ip4ip6_prefix), &saddr, sizeof(saddr));
        __builtin_memcpy(conn->d_addr + sizeof(ip4ip6_prefix), &daddr, sizeof(daddr));

        tcp->hdr_len = ETH_HLEN + hdr_len;
        break;
    }
    case ETH_P_IPV6:
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr), &proto, sizeof(proto));

        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr), &conn->s_addr, sizeof(conn->s_addr));
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr), &conn->d_addr, sizeof(conn->d_addr));

        tcp->hdr_len = ETH_HLEN + sizeof(struct ipv6hdr);
        break;
    default:
        return false;
    }

    if (proto != IPPROTO_TCP) {
        return false;
    }

    u16 port;

    switch (proto) {
    case IPPROTO_TCP:
        bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, source), &port, sizeof(port));
        conn->s_port = __bpf_htons(port);

        bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, dest), &port, sizeof(port));
        conn->d_port = __bpf_htons(port);

        u16 seq;
        bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, seq), &seq, sizeof(seq));
        tcp->seq = __bpf_htons(seq);

        u8 doff;
        bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
        doff &= 0xf0; // clean-up res1
        doff >>= 4; // move the upper 4 bits to low
        doff *= 4; // convert to bytes length

        tcp->hdr_len += doff;

        u8 flags;
        bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, ack_seq) + 4 + 1, &flags, sizeof(flags)); // read the second byte past __tcphdr->doff, again bit fields offsets
        tcp->flags = flags;

        tcp->type = IPPROTO_TCP;

        return true;
    case IPPROTO_UDP: 
        bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct udphdr, source), &port, sizeof(port));
        conn->s_port = __bpf_htons(port);
        bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct udphdr, dest), &port, sizeof(port));
        conn->d_port = __bpf_htons(port);

        tcp->hdr_len += sizeof(struct udphdr);

        tcp->type = IPPROTO_UDP;

        return true;
    }

    
    return false;
}

static __always_inline bool tcp_close(protocol_info_t *tcp) {
    return tcp->flags & (TCPHDR_FIN | TCPHDR_RST);
}

static __always_inline bool tcp_ack(protocol_info_t *tcp) {
    return tcp->flags == TCPHDR_ACK;
}

static __always_inline bool tcp_empty(protocol_info_t *tcp, struct __sk_buff *skb) {
    return tcp->hdr_len == skb->len; 
}


#ifdef BPF_DEBUG
static __always_inline void dbg_print_http_connection_info(connection_info_t *info) {
    bpf_printk("[http] s_h = %llx, s_l = %llx, d_h = %llx, d_l = %llx, s_port=%d, d_port=%d",
               *(u64 *)(&info->s_addr),
               *(u64 *)(&info->s_addr[8]),
               *(u64 *)(&info->d_addr),
               *(u64 *)(&info->d_addr[8]),
               info->s_port,
               info->d_port);
}
#else
static __always_inline void dbg_print_http_connection_info(connection_info_t *info) {
}
#endif

static __always_inline bool likely_ephemeral_port(u16 port) {
    return port >= EPHEMERAL_PORT_MIN;
}

#define __SWAP(T, x, y)                                                                            \
    {                                                                                              \
        T TMP = x;                                                                                 \
        x = y;                                                                                     \
        y = TMP;                                                                                   \
    }

// Since we track both send and receive connections, we need to sort the source and destination
// pairs in a standardized way, we choose the server way of sorting, such that the ephemeral port
// on the client is first.
static __always_inline void sort_connection_info(connection_info_t *info) {
    if (likely_ephemeral_port(info->s_port) && !likely_ephemeral_port(info->d_port)) {
        return;
    }

    if ((likely_ephemeral_port(info->d_port) && !likely_ephemeral_port(info->s_port)) ||
        (info->d_port > info->s_port)) {
        // Only sort if they are explicitly reversed, otherwise always sort source to be the larger
        // of the two ports
        __SWAP(u16, info->s_port, info->d_port);
        u8 tmp_addr[IP_V6_ADDR_LEN];
        __builtin_memcpy(tmp_addr, info->s_addr, sizeof(tmp_addr));
        __builtin_memcpy(info->s_addr, info->d_addr, sizeof(info->s_addr));
        __builtin_memcpy(info->d_addr, tmp_addr, sizeof(info->d_addr));
    }
}

#endif