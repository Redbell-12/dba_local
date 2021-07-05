#ifndef _SEND_RESET
#define _SEND_RESET

//  tcp伪头部
typedef struct _tcp_psd_header {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t zero;
	uint8_t protocol;
	uint16_t len;
}tcp_psd_header;

typedef struct _tcp_header
{
    uint16_t SrcPort;
    uint16_t DstPort;
    uint32_t SeqNum;
    uint32_t AckNum;
    uint16_t Reserved1:4;
    uint16_t HdrLength:4;
    uint16_t Fin:1;
    uint16_t Syn:1;
    uint16_t Rst:1;
    uint16_t Psh:1;
    uint16_t Ack:1;
    uint16_t Urg:1;
    uint16_t Reserved2:2;
    uint16_t Window;
    uint16_t Checksum;
    uint16_t UrgPtr;
} tcp_header;

typedef struct _ip_header {
    uint8_t  HdrLength:4;
    uint8_t  Version:4;
    uint8_t  TOS;
    uint16_t Length;
    uint16_t Id;
    uint16_t Fragment;
    uint8_t  TTL;
    uint8_t  Protocol;
    uint16_t Checksum;
    uint32_t SrcAddr;
    uint32_t DstAddr;
} ip_header;

typedef struct _replace_info {
    int value_pos[100];
	int value_len[100];
	int index;
	char mask_name[100][255];
}replace_info, *p_replace_info;

void send_reset();
void find_value(char *value, int value_len, char *mask, p_replace_info info);
void replace_request_data(char *policy_data, int policy_len);
int replace_reponse_data(p_replace_info info);
//int replace_reponse_data(char *value, char *mask, int value_len);
int waf_htoi(char *s);

#endif