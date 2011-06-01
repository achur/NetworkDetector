#include <iostream>

using namespace std;

// Function Prototypes
int runDetection(string filename);


int main(int argc, char *argv[], char *env[]) {
  if(argc != 2) {
    cout << "Usage: " + string(argv[0]) + " pcap_filename" << endl;
    return -1;
  } else {
    return runDetection(argv[1]);
  }
}

int runDetection(string filename) {
  cout << filename << endl;
}

