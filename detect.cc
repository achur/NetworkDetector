// Switch to __LINUX_BUILD if you want it
#define __BSD_BUILD

#if defined(__BSD_BUILD)
#define GETSYN(x) ((x->th_flags & TH_SYN) != 0 ? 1 : 0)
#define GETACK(x) ((x->th_flags & TH_ACK) != 0 ? 1 : 0)
#define GETRST(x) ((x->th_flags & TH_RST) != 0 ? 1 : 0)
#define GETSRCPORT(x) (ntohs(x->th_sport))
#define GETDSTPORT(x) (ntohs(x->th_dport))
#define GETSEQ(x) (ntohl(x->th_seq))
#define GETACKSEQ(x) (ntohl(x->th_ack))
#endif // defined(__BSD_BUILD)

#if defined(__LINUX_BUILD)
#define GETSYN(x) ((x->syn) != 0 ? 1 : 0)
#define GETACK(x) ((x->ack) != 0 ? 1 : 0)
#define GETRST(x) ((x->rst) != 0 ? 1 : 0)
#define GETSRCPORT(x) (ntohs(x->source))
#define GETDSTPORT(x) (ntohs(x->dest))
#define GETSEQ(x) (ntohl(x->seq))
#define GETACKSEQ(x) (ntohl(x->ack_seq))
#endif // defined(__LINUX_BUILD)

#define __IP_HDR_LENGTH(ip) (ip->ip_hl << 2)

#include <iostream>
#include "pcap.h"
#include <netinet/ip.h>
#include <arpa/inet.h>

// Here we just favor BSD format for convenience on corn, but
// to get good results, you probably want to switch to
// __LINUX_BUILD
#if !(defined __FAVOR_BSD) && defined(__BSD_BUILD)
#define __FAVOR_BSD
#include <netinet/tcp.h>
#undef __FAVOR_BSD
#else
#include <netinet/tcp.h>
#endif

using namespace std;

// Function Prototypes
void printPackets(pcap_t* pcap);


int main(int argc, char *argv[], char *env[]) {
  if(argc != 2) {
    cout << "Usage: " + string(argv[0]) + " pcap_filename" << endl;
    return -1;
  } else {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if(handle == NULL) {
      cout << string(errbuf) << endl;
    } else {
      printPackets(handle);
    }
  }
  return 0;
}

/*
 *  A little warmup and debugging
 *  Prints out all the relevant info from all the packets in the trace
 */
void printPackets(pcap_t* pcap) {
  while(true) {
    const u_char *packet_data;
    struct pcap_pkthdr *header;
    int result = pcap_next_ex(pcap, &header, &packet_data);
    if(result == -1) {
      cout << "Error in reading a packet" << endl;
    }
    if(result == -2) break;
    struct ip* ip_hdr = (struct ip*) (packet_data+14);
    if(ip_hdr->ip_p != 6) continue; // If we don't have a TCP packet.
    char src[80];
    inet_ntop(ip_hdr->ip_v == 4 ? AF_INET : AF_INET6, &(ip_hdr->ip_src), src, 80);
    char dst[80];
    inet_ntop(ip_hdr->ip_v == 4 ? AF_INET : AF_INET6, &(ip_hdr->ip_dst), dst, 80);
    struct tcphdr* tcp_hdr = (struct tcphdr*) ((char *)ip_hdr + __IP_HDR_LENGTH(ip_hdr));
    cout << "Source: " << src << ":" << GETSRCPORT(tcp_hdr) << "   Destination: " << dst << ":" << GETDSTPORT(tcp_hdr) << endl;
    cout << "SEQ: " << GETSEQ(tcp_hdr) << "    ACK: " << GETACKSEQ(tcp_hdr) << endl;
    if(GETSYN(tcp_hdr)) cout << "SYN ";
    if(GETACK(tcp_hdr)) cout << "ACK ";
    if(GETRST(tcp_hdr)) cout << "RST";
    cout << endl << endl;
  }
}

