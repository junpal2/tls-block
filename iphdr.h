#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	uint8_t version_ihl;
	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint8_t frag_offset:5;
	uint8_t more_fragment:1;
	uint8_t dont_fragment:1;
	uint8_t reserved_zero:1;
	uint8_t frag_offset2;
	uint8_t ttl;
	uint8_t proto;
	uint16_t check;
	Ip sip_;
	Ip dip_;

	Ip sip() { return ntohl(sip_); }
	Ip dip() { return ntohl(dip_); }
};
typedef IpHdr* PIpHdr;
#pragma pack(pop)

inline int ip_hdr_len(const IpHdr* ip){
	return (ip->version_ihl&0x0F)*4;
}
