#include <iostream>

using namespace std;

// Function Prototypes


int main(int argc, char *argv[], char *env[])
{
  if(argc != 2) {
    cout << "Usage: " + string(argv[0]) + " pcap_filename" << endl;
  } else {
    cout << argv[1] << endl;
  }
}