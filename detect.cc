// Switch to __LINUX_BUILD if you want it
#define __BSD_BUILD

#if defined(__BSD_BUILD)
#define GETSYN(x) ((x->th_flags & TH_SYN) > 0 ? 1 : 0)
#define GETACK(x) ((x->th_flags & TH_ACK) > 0 ? 1 : 0)
#define GETRST(x) ((x->th_flags & TH_RST) > 0 ? 1 : 0)
#define GETSRCPORT(x) (x->th_sport)
#define GETDSTPORT(x) (x->th_dport)
#define GETSEQ(x) (x->th_seq)
#endif // defined(__BSD_BUILD)

#if defined(__LINUX_BUILD)
#define GETSYN(x) ((x->syn) > 0 ? 1 : 0)
#define GETACK(x) ((x->ack) > 0 ? 1 : 0)
#endif // defined(__LINUX_BUILD)

#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

using namespace std;

// Function Prototypes
void runDetection(pcap_t* pcap);


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
      runDetection(handle);
    }
  }
  return 0;
}

void runDetection(pcap_t* pcap) {
  while(true) {
    const u_char *packet_data;
    struct pcap_pkthdr *header;
    int result = pcap_next_ex(pcap, &header, &packet_data);
    if(result == -1) {
      cout << "Error in reading a packet" << endl;
    }
    if(result == -2) break;
    struct ip* ip_hdr = (struct ip*) (packet_data+14);
    if(ip_hdr->ip_p != 6) cout << "test" << endl; // If we don't have a TCP packet.
    char src[80];
    inet_ntop(ip_hdr->ip_v == 4 ? AF_INET : AF_INET6, &(ip_hdr->ip_src), src, 80);
    char dst[80];
    inet_ntop(ip_hdr->ip_v == 4 ? AF_INET : AF_INET6, &(ip_hdr->ip_dst), dst, 80);
    struct tcphdr* tcp_hdr = (struct tcphdr*) (packet_data + 14 + ip_hdr->ip_hl * 4);
    cout << "Source: " << src << "   Destination: " << dst << endl;
    cout << "S_PORT: " << GETSRCPORT(tcp_hdr) << "   D_PORT: " << GETDSTPORT(tcp_hdr) << "  SEQ: " << GETSEQ(tcp_hdr) << endl;
    if(GETSYN(tcp_hdr) > 0) cout << "SYN ";
    if(GETACK(tcp_hdr) > 0) cout << "ACK ";
    if(GETRST(tcp_hdr) > 0) cout << "RST";
    cout << endl << endl;
  }
}

