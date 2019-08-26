#include "netfilter_test.h"
using namespace std;
string url = "";

static ST_JE_NETFILTER_CHECK print_pkt (struct nfq_data *tb)
{
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    int ret;
    unsigned char *data;
    struct ST_JE_TCP_Packet *packet_header;
    unsigned char *http_data;
    string s;
    ST_JE_NETFILTER_CHECK nfcheck = {0, true};

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        nfcheck.id = ntohl(ph->packet_id);
    }
    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int hlen = ntohs(hwph->hw_addrlen);
    }

    ret = nfq_get_payload(tb, &data);
    packet_header = reinterpret_cast<ST_JE_TCP_Packet*>(data);
    if(packet_header->ip_header.ip_p == IPPROTO_TCP){
        if(ntohs(packet_header->tcp_header.th_dport) == 80 || ntohs(packet_header->tcp_header.th_sport) == 80){
            int ip_header_len = packet_header->ip_header.ip_hl*4;
            int tcp_header_len = packet_header->tcp_header.th_off*4;
            http_data = (unsigned char*)malloc(ret - ip_header_len - tcp_header_len);
            memcpy(http_data, reinterpret_cast<unsigned char*>(packet_header)+(ip_header_len + tcp_header_len), ret - ip_header_len - tcp_header_len);
            if(NULL != strstr((char*)http_data, url.c_str())){
                nfcheck.check = false;
            }
            free(http_data);
        }
    }
    return nfcheck;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    ST_JE_NETFILTER_CHECK nfcheck = print_pkt(nfa);

    if (nfcheck.check) {
        printf("Accept\n");
        return nfq_set_verdict(qh, nfcheck.id, NF_ACCEPT, 0, NULL);
    } else {
        printf("Drop\n");
        return nfq_set_verdict(qh, nfcheck.id, NF_DROP, 0, NULL);
    }
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    url = argv[1];
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    //printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
