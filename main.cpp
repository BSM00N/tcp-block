#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <vector>
#include "ethhdr.h"
#include "tcphdr.h"
#include "iphdr.h"

// Global variables
Mac myMac;
Ip myIp;

struct PseudoHeader {
    uint32_t sourceAddress;
    uint32_t destAddress;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcpLength;
};

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

void debug(char* ptr, uint32_t num) {
    for (int i = 0; i < num; i++)
        printf("%02X ", ptr[i]);
}

int getAddresses(const char* interface, Mac* myMac, Ip* myIp) {   
    struct ifreq ifr;
    int sockfd, ret;
    char ipstr[30] = {0};
    uint8_t macbuf[6] = {0};

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("socket() FAILED\n");
        return -1;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);

    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr); 
    if (ret < 0) {
        printf("ioctl() FAILED\n");
        close(sockfd);
        return -1;
    }
    memcpy(macbuf, ifr.ifr_hwaddr.sa_data, 6); 
    *myMac = Mac(macbuf);

    ret = ioctl(sockfd, SIOCGIFADDR, &ifr); 
    if (ret < 0) {
        printf("ioctl() FAILED\n");
        close(sockfd);
        return -1;
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ipstr, sizeof(struct sockaddr));
    *myIp = Ip(ipstr);
    close(sockfd);

    return 0;
}

uint16_t calculateChecksum(uint16_t* ptr, int len) {
    uint32_t sum = 0;
    uint16_t odd = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        *(uint8_t *)(&odd) = (*(uint8_t *)ptr);
        sum += odd;
    }

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}

void sendFinPacket(pcap_t* handle, PIpHdr ipHeader, PTcpHdr tcpHeader, uint32_t tcpDataLen) {
    int rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int value = 1;
    setsockopt(rawSock, IPPROTO_IP, IP_HDRINCL, (char *)&value, sizeof(value));

    struct sockaddr_in rawAddr;
    rawAddr.sin_family = AF_INET;
    rawAddr.sin_port = tcpHeader->sport;
    rawAddr.sin_addr.s_addr = (uint32_t)ipHeader->sip_;

    const char* tcpData = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
    uint16_t ipHeaderLen = sizeof(IpHdr), tcpHeaderLen = sizeof(TcpHdr), tcpDataLenMy = strlen(tcpData);
    uint16_t totalLen = ipHeaderLen + tcpHeaderLen + strlen(tcpData);

    std::vector<char> packet(totalLen + 1);
    memset(packet.data(), 0, totalLen + 1);

    PIpHdr ipHeaderMy = (PIpHdr)packet.data();
    PTcpHdr tcpHeaderMy = (PTcpHdr)(packet.data() + ipHeaderLen);
    memcpy(packet.data() + ipHeaderLen + tcpHeaderLen, tcpData, tcpDataLenMy);

    tcpHeaderMy->sport = tcpHeader->dport;
    tcpHeaderMy->dport = tcpHeader->sport;
    tcpHeaderMy->seqnum = tcpHeader->acknum;
    tcpHeaderMy->acknum = htonl(ntohl(tcpHeader->seqnum) + tcpDataLen);
    tcpHeaderMy->th_off = tcpHeaderLen / 4;
    tcpHeaderMy->flags = 0b00010001;
    tcpHeaderMy->win = htons(60000);

    ipHeaderMy->ip_len = ipHeaderLen / 4;
    ipHeaderMy->ip_v = 4;
    ipHeaderMy->total_len = htons(totalLen);
    ipHeaderMy->ttl = 128;
    ipHeaderMy->proto = 6;
    ipHeaderMy->sip_ = ipHeader->dip_;
    ipHeaderMy->dip_ = ipHeader->sip_;

    PseudoHeader psdHeader = {};
    psdHeader.sourceAddress = ipHeader->dip_;
    psdHeader.destAddress = ipHeader->sip_;
    psdHeader.protocol = IPPROTO_TCP;
    psdHeader.tcpLength = htons(tcpHeaderLen + tcpDataLenMy);

    uint32_t tcpChecksum = calculateChecksum((uint16_t*)tcpHeaderMy, tcpHeaderLen + tcpDataLenMy) + calculateChecksum((uint16_t*)&psdHeader, sizeof(PseudoHeader));
    tcpHeaderMy->check = (tcpChecksum & 0xffff) + (tcpChecksum >> 16);
    ipHeaderMy->check = calculateChecksum((uint16_t*)ipHeaderMy, ipHeaderLen);

    if (sendto(rawSock, packet.data(), totalLen, 0, (struct sockaddr *)&rawAddr, sizeof(rawAddr)) < 0) {
        perror("Send failed");
    }
    close(rawSock);
}

void sendRstPacket(pcap_t* handle, const u_char* packetData, PIpHdr ipHeader, PTcpHdr tcpHeader, uint32_t ipHeaderLen, uint32_t tcpDataLen) {
    uint32_t newPktLen = sizeof(EthHdr) + ipHeaderLen + sizeof(TcpHdr);
    std::vector<char> newPacket(newPktLen + 1);
    memset(newPacket.data(), 0, newPktLen + 1);
    memcpy(newPacket.data(), packetData, newPktLen);

    PEthHdr ethernetHeader = (PEthHdr)newPacket.data();
    ipHeader = (PIpHdr)(newPacket.data() + sizeof(EthHdr));
    tcpHeader = (PTcpHdr)(newPacket.data() + sizeof(EthHdr) + ipHeaderLen);

    ethernetHeader->smac_ = myMac;
    ipHeader->total_len = htons(ipHeaderLen + sizeof(TcpHdr));
    ipHeader->check = 0;
    tcpHeader->th_off = sizeof(TcpHdr) / 4;
    tcpHeader->seqnum = htonl(ntohl(tcpHeader->seqnum) + tcpDataLen);
    tcpHeader->flags = 0b00010100;
    tcpHeader->check = 0;

    PseudoHeader psdHeader = {};
    psdHeader.sourceAddress = ipHeader->sip_;
    psdHeader.destAddress = ipHeader->dip_;
    psdHeader.protocol = IPPROTO_TCP;
    psdHeader.tcpLength = htons(sizeof(TcpHdr));

    uint32_t tcpChecksum = calculateChecksum((uint16_t*)tcpHeader, sizeof(TcpHdr)) + calculateChecksum((uint16_t*)&psdHeader, sizeof(PseudoHeader));
    tcpHeader->check = (tcpChecksum & 0xffff) + (tcpChecksum >> 16);
    ipHeader->check = calculateChecksum((uint16_t*)ipHeader, ipHeaderLen);

    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(newPacket.data()), newPktLen)) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 0;
    }

    char* dev = strdup(argv[1]);
    getAddresses(dev, &myMac, &myIp);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    char* pattern = strdup(argv[2]);

    struct pcap_pkthdr* header;
    const u_char* packetData;
    PEthHdr ethernetHeader;
    PIpHdr ipHeader;
    PTcpHdr tcpHeader;
    int res;

    while (true) {
        res = pcap_next_ex(handle, &header, &packetData);
        if (res == 0) continue;
        else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ethernetHeader = (PEthHdr)packetData;
        if (ethernetHeader->type() == EthHdr::Ip4) {
            ipHeader = (PIpHdr)(packetData + sizeof(EthHdr));
            uint32_t ipHeaderLen = ipHeader->ip_len * 4;
            uint32_t ipPacketLen = ntohs(ipHeader->total_len);
            uint32_t packetLen = ipPacketLen + sizeof(EthHdr);

            if (ipHeader->proto == 6) {
                tcpHeader = (PTcpHdr)((uint8_t*)ipHeader + ipHeaderLen);
                uint32_t tcpHeaderLen = tcpHeader->th_off * 4;
                uint32_t tcpDataLen = ipPacketLen - ipHeaderLen - tcpHeaderLen;

                if (tcpDataLen == 0) continue;

                std::vector<char> tcpData(tcpDataLen + 1);
                memset(tcpData.data(), 0, tcpDataLen + 1);
                strncpy(tcpData.data(), (char*)((uint8_t*)tcpHeader + tcpHeaderLen), tcpDataLen);

                if (strstr(tcpData.data(), pattern) && !strncmp(tcpData.data(), "GET", 3)) {
                    sendFinPacket(handle, ipHeader, tcpHeader, tcpDataLen);
                    sendRstPacket(handle, packetData, ipHeader, tcpHeader, ipHeaderLen, tcpDataLen);
                }
            }
        }
    }

    free(dev);
    free(pattern);
    pcap_close(handle);
    return 0;
}
