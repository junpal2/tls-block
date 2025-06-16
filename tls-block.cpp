#include <cstdio>
#include <string>
#include <map>
#include <tuple>
#include <string.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "iphdr.h"
#include "ethhdr.h"
#include "tcphdr.h"
#include "mac.h"

#pragma pack(push, 1)
struct TlsRecordHeader
{
    uint8_t content_type;
    uint16_t version;
    uint16_t length;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TlsHandshakeHeader
{
    uint8_t handshake_type;
    uint8_t length[3];
};
#pragma pack(pop)

struct Key
{
    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint16_t dport;
    bool operator<(const Key &r) const
    {
        return std::tie(sip, sport, dip, dport) < std::tie(r.sip, r.sport, r.dip, r.dport);
    }
};

#pragma pack(push, 1)
struct PseudoHeader
{
    uint32_t src;     // 네트워크 바이트 순서(sip_)
    uint32_t dst;     // 네트워크 바이트 순서(dip_)
    uint8_t reserved; // 0
    uint8_t protocol; // IPPROTO_TCP
    uint16_t tcp_len; // htons( TCP 헤더 + 데이터 길이 )
};
#pragma pack(pop)

Mac attacker_mac;
int sd = 0;

void usage()
{
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

int get_attacker_mac(const char *interface)
{
    struct ifreq ifr;
    int sockfd, ret;
    uint8_t macbuf[6] = {0};

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        printf("socket() FAILED\n");
        return -1;
    }
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0)
    {
        printf("ioctl() FAILED\n");
        close(sockfd);
        return -1;
    }
    memcpy(macbuf, ifr.ifr_hwaddr.sa_data, 6);
    attacker_mac = Mac(macbuf);
    close(sockfd);
    return 1;
}

uint16_t Checksum(uint16_t *ptr, int len)
{
    uint32_t sum = 0;

    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
    {
        sum += (uint16_t)(*(uint8_t *)ptr << 8);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

void ipChecksum(IpHdr *ip_hdr)
{
    ip_hdr->check = 0;
    ip_hdr->check = Checksum((uint16_t *)ip_hdr, ip_hdr_len(ip_hdr));
}
void tcpChecksum(IpHdr *ip_hdr, TcpHdr *tcp_hdr, uint8_t *data, size_t data_len)
{
    uint32_t sum = 0;
    const uint16_t tcp_len = sizeof(TcpHdr) + data_len;

    PseudoHeader psd;
    psd.src = ip_hdr->sip_;
    psd.dst = ip_hdr->dip_;
    psd.reserved = 0;
    psd.protocol = IPPROTO_TCP;
    psd.tcp_len = htons(sizeof(TcpHdr) + data_len);

    size_t buf_len = sizeof(PseudoHeader) + sizeof(TcpHdr) + data_len;
    uint8_t *buf = (uint8_t *)alloca(buf_len);
    memcpy(buf, &psd, sizeof(PseudoHeader));

    uint8_t *p = buf + sizeof(PseudoHeader);
    tcp_hdr->crc = 0;
    memcpy(p, tcp_hdr, sizeof(TcpHdr));

    p += sizeof(TcpHdr);
    if (data_len > 0)
    {
        memcpy(p, data, data_len);
    }

    tcp_hdr->crc = Checksum(reinterpret_cast<uint16_t *>(buf), (int)buf_len);
}

/*
   TLS Client Hello \uad6c\uc870 (\ucc38\uace0\uc6a9):
   TLS Record Header (5 bytes)
   - Content Type (1 byte): 0x16 (Handshake)
   - Version (2 bytes): e.g., 0x0301 for TLS 1.0
   - Length (2 bytes): \uc804\uccb4 \ud578\ub4dc\uc170\uc774\ud06c \uae38\uc774
   TLS Handshake Header (4 bytes)
   - Handshake Type (1 byte): 0x01 (Client Hello)
   - Length (3 bytes): Client Hello \uba54\uc2dc\uc9c0 \uae38\uc774
   Client Hello \uad6c\uc870
   - Version (2 bytes)
   - Random (32 bytes)
   - Session ID Length (1 byte)
   - Session ID (\uac00\ubcc0)
   - Cipher Suites Length (2 bytes)
   - Cipher Suites (\uac00\ubcc0)
   - Compression Methods Length (1 byte)
   - Compression Methods (\uac00\ubcc0)
   - Extensions Length (2 bytes)
   - Extensions (\uac00\ubcc0)
   - Extension Type (2 bytes)
   - Extension Length (2 bytes)
   - Extension Data
   - SNI Extension\uc77c \uacbd\uc6b0:
   - Server Name List Length (2 bytes)
   - Name Type (1 byte): 0 = host_name
   - Name Length (2 bytes)
   - Name (hostname string)
   */
const char *extract_sni(const uint8_t *data, size_t len)
{
    size_t pos = sizeof(TlsRecordHeader) + sizeof(TlsHandshakeHeader);

    if (len <= pos + 34)
        return NULL;
    pos += 34;

    if (pos + 1 > len)
        return NULL;
    uint8_t session_id_len = data[pos];
    if (pos + 1 + session_id_len > len)
        return NULL;
    pos += 1 + session_id_len;

    if (pos + 2 > len)
        return NULL;
    uint16_t cipher_suites_len = (data[pos] << 8) | data[pos + 1];
    printf("cipher_suites_len: %u (pos: %zu, len: %zu)\n", cipher_suites_len, pos, len);
    if (pos + 2 + cipher_suites_len > len)
        return NULL;
    pos += 2 + cipher_suites_len;

    if (pos + 1 > len)
        return NULL;
    uint8_t compression_methods_len = data[pos];
    if (pos + 1 + compression_methods_len > len)
        return NULL;
    pos += 1 + compression_methods_len;
    if (pos + 2 > len)
        return NULL;
    pos += 2;

    printf("TLS total len: %zu\n", len);
    printf("Initial parse position: %zu\n", pos);

    while (pos + 4 <= len)
    {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_size = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (ext_type == 0x00)
        { // SNI Extension
            if (pos + 5 > len)
                return NULL;
            uint8_t name_type = data[pos + 2];
            uint16_t sni_len = (data[pos + 3] << 8) | data[pos + 4];

            printf("SNI name_type: %d, sni_len: %d\n", name_type, sni_len);

            if (name_type != 0 || pos + 5 + sni_len > len)
                return NULL;
            printf("SNI found!\n");

            return (const char *)(&data[pos + 5]);
        }
        pos += ext_size;
    }
    return NULL;
}

int send_forward_rst(pcap_t *pcap, const EthHdr *org_eth, const IpHdr *org_ip, const TcpHdr *org_tcp, int org_tcp_data_len, Mac my_mac)
{
    uint8_t packet[sizeof(EthHdr) + sizeof(IpHdr) + sizeof(TcpHdr)] = {0};
    EthHdr *eth_hdr = reinterpret_cast<EthHdr *>(packet);
    IpHdr *ip_hdr = reinterpret_cast<IpHdr *>(packet + sizeof(EthHdr));
    TcpHdr *tcp_hdr = reinterpret_cast<TcpHdr *>(packet + sizeof(EthHdr) + sizeof(IpHdr));

    eth_hdr->smac_ = my_mac;
    eth_hdr->dmac_ = org_eth->dmac_;
    eth_hdr->type_ = htons(EthHdr::Ip4);

    ip_hdr->version_ihl = 0x45;
    ip_hdr->tos = 0;
    ip_hdr->total_len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    ip_hdr->id = htons(rand());
    ip_hdr->frag_offset = htons(0x4000);
    ip_hdr->ttl = org_ip->ttl;
    ip_hdr->proto = 6;
    ip_hdr->sip_ = org_ip->sip_;
    ip_hdr->dip_ = org_ip->dip_;
    ipChecksum(ip_hdr);

    tcp_hdr->sport = org_tcp->sport;
    tcp_hdr->dport = org_tcp->dport;
    tcp_hdr->seqnum = htonl(ntohl(org_tcp->seqnum) + org_tcp_data_len);
    tcp_hdr->acknum = org_tcp->acknum;
    tcp_hdr->data_offset_reserved = 0x50;
    tcp_hdr->flags = 0x14;
    tcp_hdr->win = 0;
    tcp_hdr->urgptr = 0;
    tcpChecksum(ip_hdr, tcp_hdr, nullptr, 0);

    if (pcap_sendpacket(pcap, packet, sizeof(packet)) != 0)
    {
        printf("Send failed-forward\n");
    }
    else
        printf("Forward RST packet sent\n");
}

int send_backward_rst(PIpHdr ip, PTcpHdr tcp, int data_len, int sd)
{
    uint8_t packet[sizeof(IpHdr) + sizeof(TcpHdr)] = {0};
    PIpHdr new_ip = (PIpHdr)(packet);
    PTcpHdr new_tcp = (PTcpHdr)(packet + sizeof(IpHdr));

    *new_ip = *ip;
    new_ip->version_ihl = 0x45;
    new_ip->tos = 0;
    new_ip->total_len = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    new_ip->id = htons(rand());
    new_ip->sip_ = ip->dip_;
    new_ip->dip_ = ip->sip_;
    new_ip->check = 0;
    ipChecksum(new_ip);

    new_tcp->sport = tcp->dport;
    new_tcp->dport = tcp->sport;
    new_tcp->seqnum = tcp->acknum;
    new_tcp->acknum = htonl(ntohl(tcp->seqnum) + data_len);
    new_tcp->data_offset_reserved = 0x50;
    new_tcp->flags = 0x14;
    new_tcp->win = 0;
    new_tcp->urgptr = 0;
    new_tcp->crc = 0;
    tcpChecksum(new_ip, new_tcp, nullptr, 0);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip->sip_;

    int ret = sendto(sd, packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin));
    close(sd);
    if (ret < 0)
    {
        perror("Send failed-backward\n");
        return -1;
    }
    else
        printf("Backward RST packet sent\n");
    return 0;
}

int main(int argc, char *argv[])
{
    std::map<Key, std::string> segmap;

    if (argc != 3)
    {
        usage();
        return -1;
    }
    char *dev = argv[1];
    const char *target = argv[2];
    printf("Target: %s\n", target);

    if (get_attacker_mac(dev) < 0)
    {
        printf("MAC error\n");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    if (!handle)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int on = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    while (1)
    {
        struct pcap_pkthdr *hdr;
        const u_char *pkt;

        if (pcap_next_ex(handle, &hdr, &pkt) <= 0)
            continue;

        PEthHdr eth = (PEthHdr)pkt;
        if (eth->type() != EthHdr::Ip4)
            continue;

        PIpHdr ip = (PIpHdr)(pkt + sizeof(EthHdr));
        if (ip->proto != 6)
            continue;

        int ip_hl = ip_hdr_len(ip);
        PTcpHdr tcp = (PTcpHdr)((u_char *)ip + ip_hl);
        if (ntohs(tcp->dport) != 443)
            continue;

        int tcp_hl = tcp_hdr_len(tcp);

        const uint8_t *data = pkt + sizeof(EthHdr) + ip_hl + tcp_hl;
        int data_len = ntohs(ip->total_len) - ip_hl - tcp_hl;
        if (data_len <= (int)(sizeof(TlsRecordHeader) + sizeof(TlsHandshakeHeader)))
            continue;

        Key key{ip->sip(), ntohs(tcp->sport), ip->dip(), ntohs(tcp->dport)};
        segmap[key].append((const char *)data, data_len);
        printf("data_len: %d\n", data_len);
        const std::string &bufstr = segmap[key];

        printf("raw TLS: %02x %02x %02x %02x %02x %02x\n",
               data[0], data[1], data[2], data[3], data[4], data[5]);

        const TlsRecordHeader *record = reinterpret_cast<const TlsRecordHeader *>(bufstr.data());
        if (record->content_type != 0x16)
            continue;

        const TlsHandshakeHeader *handshake = reinterpret_cast<const TlsHandshakeHeader *>(bufstr.data() + sizeof(TlsRecordHeader));
        if (handshake->handshake_type != 0x01)
            continue;

        printf("Accumulated len: %zu\n", bufstr.size());
        int total_len = segmap[key].size();
        const char *sni = extract_sni((const uint8_t *)bufstr.data(), bufstr.size());
        if (sni)
            printf("SNI: %s\n", sni);
        if (sni && memmem(sni, strlen(sni), target, strlen(target)))
        {
            printf("[DBG] total_len=%d, orig_seq=%u, new_seq=%u\n",
                   total_len,
                   ntohl(tcp->seqnum),
                   ntohl(htonl(ntohl(tcp->seqnum) + total_len)));

            send_backward_rst(ip, tcp, total_len, sd);
            send_forward_rst(handle, eth, ip, tcp, total_len, attacker_mac);
            segmap.erase(key);
        }
    }
    pcap_close(handle);
    return 0;
}

