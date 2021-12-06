#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <map>
#include <unistd.h>
#include "mac.h"
#include "radiotap.h"
#include "beaconframe.h"

void usage(){
    std::cout << "syntax : airodump <interface>" << std::endl;
    std::cout << "sample : airodump mon0" << std::endl;
}

struct SSID
{
    uint8_t num;
    uint8_t len;
};

struct Airo{
    std::string SSID;
    Mac BSSID;
    uint8_t Beacons;
    int8_t PWR;
};

std::map<Mac, Airo> airomap;


void print(){
    system("clear");
    std::cout << " BSSID                PWR    Beacons    ESSID        " << std::endl;
    for(auto airo : airomap){
        std::cout << " " << std::string(airo.second.BSSID) << "    ";
        std::cout << std::setw(3) << std::to_string(airo.second.PWR)  << "    ";
        std::cout << std::setw(7) << std::to_string(airo.second.Beacons) << "    ";
        std::cout << airo.second.SSID << std::endl; 
    }
}

int main(int argc, char *argv[])
{
    if(argc != 2){
        usage();
        exit(0);
    }

    const char* interface =argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if(handle == NULL){
        fprintf(stderr,"couldn't open device %s: %s\n", interface, errbuf);
        return -1;
    }

    system("clear");
    std::cout << " BSSID                PWR    Beacons    ESSID        " << std::endl;
    while(true){
        struct pcap_pkthdr* header;
		const u_char* p;
		int res = pcap_next_ex(handle, &header, &p);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
		}

        struct RadHdr *rd = (struct RadHdr *)p;
        struct BeaconHdr *bc = (struct BeaconHdr *)(p + rd->len());
        struct Airo airo;

        if(bc->fc_.type != 0 || bc->fc_.subtype != 0x08){
            continue;
        }

        if(rd->present_flags_.dbm_antenna_sig==1){
            airo.PWR = getPWR(rd);
        }
        else{
            airo.PWR = 0;
        }

        airo.BSSID = bc->bssid_;
        
        struct Beaconfixed *fix = (struct Beaconfixed *)(p + rd->len() + sizeof(BeaconHdr));
        struct SSID *ssid = (struct SSID*)(p + rd->len() + sizeof(BeaconHdr) + sizeof(Beaconfixed));

        if(airomap.count(airo.BSSID) != 0){
            airomap[airo.BSSID].Beacons++;
        }
        else{
            u_char *ssid_ptr = (u_char *)ssid + 2;
            std::string ssid_temp;
            for(int i=0; i<ssid->len; i++){
                ssid_temp.push_back(*ssid_ptr++);
            }
            airo.SSID = ssid_temp;
            airomap.insert({airo.BSSID, airo});
        }
        print();
    }
}