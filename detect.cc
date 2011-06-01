#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <pcap.h>

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
    
  }
}

