#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>	/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <string>

#include <libnetfilter_queue/libnetfilter_queue.h>

struct ST_JE_TCP_Packet{
    struct libnet_ipv4_hdr ip_header;
    struct libnet_tcp_hdr tcp_header;
};
struct ST_JE_NETFILTER_CHECK{
    u_int32_t id;
    bool check;
};

void dump(unsigned char* buf, int size);
