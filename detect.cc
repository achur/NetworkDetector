// Switch to __LINUX_BUILD if you only have the linux headers.
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
#include <map>
#include "pcap.h"
#include <netinet/ip.h>
#include <arpa/inet.h>

// Here we just favor BSD format for convenience on corn, but
// to get good results on most linux boxes, you probably want 
// to switch to __LINUX_BUILD
#if !(defined __FAVOR_BSD) && defined(__BSD_BUILD)
#define __FAVOR_BSD
#include <netinet/tcp.h>
#undef __FAVOR_BSD
#else
#include <netinet/tcp.h>
#endif

struct ip_pair {
  in_addr src;
  in_addr dst;
  
  ip_pair(in_addr s, in_addr d) {
    src = s;
    dst = d;
  }
  
  inline bool operator<(const ip_pair& other) {
    return memcmp(&src, &other.src, sizeof(in_addr)) < 0 ||
      (memcmp(&src, &other.src, sizeof(in_addr)) == 0 && memcmp(&dst, &other.dst, sizeof(in_addr)) < 0);
  }
  
  inline bool operator==(const ip_pair& other) {
    return memcmp(&src, &other.src, sizeof(in_addr)) == 0 && memcmp(&dst, &other.dst, sizeof(in_addr)) == 0;
  } 
};

struct scan_request {
  u_short sport;
  u_short dport;
  tcp_seq seq;
  
  scan_request(u_short sp, u_short dp, tcp_seq se) {
    sport = sp;
    dport = dp;
    seq = se;
  }
  
  scan_request getSynFromSynAck(tcp_seq ack) {
    return scan_request(dport, sport, ack - 1);
  }
  
  inline bool operator<(const scan_request& other) {
    return sport < other.sport ||
           (sport == other.sport && dport < other.dport) ||
           (sport == other.sport && dport == other.dport && seq < other.seq);
  }
  
  inline bool operator==(const scan_request& other) {
    return sport == other.sport && dport == other.dport && seq == other.seq;
  }
};

// Bad style; be careful not to run over any STL.
using namespace std;

// Function Prototypes
void printPackets(pcap_t* pcap);
void printTCPPacket(ip* ip_hdr, tcphdr* tcp_hdr);
void buildMap(pcap_t* pcap, map<ip_pair, map<scan_request, int> >& responseMap);
void mapHandleTCPPacket(ip* ip_hdr, tcphdr* tcp_hdr, map<ip_pair, map<scan_request, int> >& responseMap);



int main(int argc, char *argv[], char *env[])
{
  if(argc != 2) {
    cout << "Usage: " + string(argv[0]) + " pcap_filename" << endl;
    return -1;
  } else {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if(handle == NULL) {
      cout << string(errbuf) << endl;
    } else {
      // printPackets(handle);
      map<ip_pair, map<scan_request, int> > responseMap;
      buildMap(handle, responseMap);
    }
  }
  return 0;
}

/*
 *  A little warmup and debugging
 *  Prints out all the relevant info from all the packets in the trace
 */
void printPackets(pcap_t* pcap)
{
  while(true) {
    const u_char *packet_data;
    struct pcap_pkthdr *header;
    int result = pcap_next_ex(pcap, &header, &packet_data);
    if(result == -1) {
      cout << "Error in reading a packet" << endl;
    }
    if(result == -2) break;
    struct ip* ip_hdr = (struct ip*) (packet_data+14);
    struct tcphdr* tcp_hdr = (struct tcphdr*) ((char *)ip_hdr + __IP_HDR_LENGTH(ip_hdr));
    if(ip_hdr->ip_p != 6) continue; // If we don't have a TCP packet, go to next one.
    printTCPPacket(ip_hdr, tcp_hdr);
  }
}

/*
 *  Prints out the single TCP packet with the given headers
 */
void printTCPPacket(ip* ip_hdr, tcphdr* tcp_hdr)
{
  char src[80]; char dst[80];
  inet_ntop(ip_hdr->ip_v == 4 ? AF_INET : AF_INET6, &(ip_hdr->ip_src), src, 80);
  inet_ntop(ip_hdr->ip_v == 4 ? AF_INET : AF_INET6, &(ip_hdr->ip_dst), dst, 80);
  cout << "Source: " << src << ":" << GETSRCPORT(tcp_hdr) 
       << "   Destination: " << dst << ":" << GETDSTPORT(tcp_hdr) << endl;
  cout << "SEQ: " << GETSEQ(tcp_hdr) << "    ACK: " << GETACKSEQ(tcp_hdr) << endl;
  if(GETSYN(tcp_hdr)) cout << "SYN ";
  if(GETACK(tcp_hdr)) cout << "ACK ";
  if(GETRST(tcp_hdr)) cout << "RST";
  cout << endl << endl;
}

/*
 *  Go through each packet and send it to be processed into the map.
 */
void buildMap(pcap_t* pcap, map<ip_pair, map<scan_request, int> >& responseMap)
{  
  while(true) {
    const u_char *packet_data;
    struct pcap_pkthdr *header;
    int result = pcap_next_ex(pcap, &header, &packet_data);
    if(result == -1) {
      cout << "Error in reading a packet" << endl;
    }
    if(result == -2) break;
    struct ip* ip_hdr = (struct ip*) (packet_data+14);
    struct tcphdr* tcp_hdr = (struct tcphdr*) ((char *)ip_hdr + __IP_HDR_LENGTH(ip_hdr));
    if(ip_hdr->ip_p != 6) continue; // If we don't have a TCP packet, go to next one.
    mapHandleTCPPacket(ip_hdr, tcp_hdr, responseMap);
  }
}


/*
 *  Go through TCP packet and check if it is a SYN packet or SYN ACK.
 
 *  If it is a SYN, go to (or add a new entry to) to the map with the 
 *  appropriate ip_pair and add a pair to its map: (sr, 1) where sr is
 *  the scan_request matching the SYN packet.
 *
 *  If it is a SYN ACK, if you can find it, go to the appropriate ip_pair
 *  (dst, src) and if that map exists, go to the appropriate scan_request
 *  (found by calling sr.getSynFromSynAck(ackNum)) and see if we can locate
 *  it in the map.  If we can, change its value to 0 (indicating that the
 *  original SYN has been responded to).
 */
void mapHandleTCPPacket(ip* ip_hdr, tcphdr* tcp_hdr, map<ip_pair, map<scan_request, int> >& responseMap)
{
  // Fill this in
}

