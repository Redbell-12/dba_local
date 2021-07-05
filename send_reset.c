/*send_reset.c
*
*
*/
//#include "head.h"
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include "head.h"
#include "send_reset.h"
#include "headfile/find_str/find_str.h"
#include "define.h"
#include "head.c"

uint8_t reset_packet[54] = {0};


#define REDUCE16(_x)	({ uint32_t x = _x;	\
	x = (x & 0xffff) + (x >> 16);		\
	x = (x & 0xffff) + (x >> 16);		\
	x; } )

#define REDUCE32(_x)	({ uint64_t x = _x;	\
	x = (x & 0xffffffff) + (x >> 32);	\
	x = (x & 0xffffffff) + (x >> 32);	\
	x; } )

int waf_htoi(char *s)
{	int value, c;
	c = ((unsigned char *)s)[0];
	if (isupper(c))
		c = tolower(c);
	value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;
	c = ((unsigned char *)s)[1];
	if (isupper(c))
		c = tolower(c);
	value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
	return (value);
}

uint32_t sum32u(const unsigned char *addr, int count)
{	uint64_t sum = 0;
	const uint32_t *p = (uint32_t *)addr;
	for (; count >= 32; count -= 32) {
		sum += (uint64_t)p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7];
		p += 8;
	}
	if (count & 0x10) {
		sum += (uint64_t)p[0] + p[1] + p[2] + p[3];
		p += 4;
	}
	if (count & 8) {
		sum += (uint64_t)p[0] + p[1];
		p += 2;
	}
	if (count & 4)
		sum += *p++;
	addr = (const unsigned char *)p;
	if (count & 2) {
		sum += *(uint16_t *)addr;
		addr += 2;
	}
	if (count & 1)
		sum += *addr;
	sum = REDUCE32(sum);
	return REDUCE16(sum);
}

static uint16_t wrapsum(uint32_t sum)	{
	sum = ~sum & 0xFFFF;	
	return (htons(sum));
}


uint16_t checksum(void *pseudo_header, uint16_t pseudo_header_len, void *data, uint32_t len)
{
    const uint16_t *data16 = (const uint16_t *)pseudo_header;
    size_t len16 = pseudo_header_len >> 1;
   	uint32_t sum = 0;
    size_t i;

    // Pseudo header:
    for (i = 0; i < len16; i++)
    {
        sum += (uint32_t)data16[i];
    }

    // Main data:
    data16 = (const uint16_t *)data;
    len16 = len >> 1;
    for (i = 0; i < len16; i++)
    {
        sum += (uint32_t)data16[i];
    }

    if (len & 0x1)
    {
        const uint8_t *data8 = (const uint8_t *)data;
        sum += (uint16_t)data8[len-1];
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (sum >> 16);
    sum = ~sum;
    return (uint16_t)sum;
}

# if 0 
int pkt_send_reset_data(net_ring *reset_txring, uint32_t *reset_txring_cur, int reset_option, int tcp_len)	//tcp_len is length of DATA
{
	uint8_t pkttemp[]={0x11,0x11,0x11,0x11,0x11};
	uint8_t pktzero[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	printf("test bug begin reset!!!!\n");

	int Reset_http_data_len;
	if(reset_option==0)
	{	Reset_http_data_len=0;		
	}
	//int tcp_no_data_len = 6;
	unsigned char *testreset = (unsigned char *)malloc(sizeof(unsigned char)*(layer2_len + 40+6));
	printf("~reset length is %d\n", layer2_len + 40+6);
	memcpy(testreset,buf_share,layer2_len+40+6);

	memcpy(testreset,buf_share+6,6);//De_mac
	memcpy(testreset+6,buf_share+0,6);//Src_mac

	int IP_Len=htons(0x0028);
	memcpy(testreset+layer2_len+2,&IP_Len,2);//IP_Len
	memcpy(testreset+layer2_len+12,buf_share+layer2_len+16,4);//IP_Src
	memcpy(testreset+layer2_len+16,buf_share+layer2_len+12,4);//IP_De
	*(testreset+layer2_len+10)=0x00;//IP_Chksum_Set_Zero
	*(testreset+layer2_len+11)=0x00;
	int IP_Chksum=htons(wrapsum(sum32u((unsigned char *)(testreset+layer2_len), 20)));
	memcpy(testreset+layer2_len+10,&IP_Chksum,2);//IP_Chksum_Cal
//=====
	memcpy(testreset+layer2_len+20,buf_share+layer2_len+22,2);//TCP_Sport
	memcpy(testreset+layer2_len+22,buf_share+layer2_len+20,2);//TCP_Dport

	memcpy(testreset+layer2_len+24,buf_share+layer2_len+28,4);//TCP_Seq_nodata
	
	unsigned int ack_next = *(buf_share+layer2_len+31)+1;
	printf("ack_next is %d\n", ack_next);

	//long int My_ack=htonl(ntohl(*(long int *)(buf_share+layer2_len+24))+1);
	long int My_ack=htonl(ntohl(*(long int *)(buf_share+layer2_len+24))+(long int)tcp_len);
	

	memcpy(testreset+layer2_len+28,&My_ack,4);//TCP_Ack_nodata
	//memcpy(testreset+layer2_len+28,pktzero,4);//TCP_Ack_nodata

	*(testreset+layer2_len+32)=0x50;//TCP_Len
	if(reset_option==0){
		*(testreset+layer2_len+33)=0x14;//TCP_Flag
		*(testreset+layer2_len+34)=0x00;//window size
		*(testreset+layer2_len+35)=0x00;
	}
	*(testreset+layer2_len+36)=0x00;
	*(testreset+layer2_len+37)=0x00;//TCP_Chksum_Set_Zero
	*(testreset+layer2_len+38)=0x00;//urgent pointer
	*(testreset+layer2_len+39)=0x00;
	memcpy(testreset+layer2_len+40, pktzero, 6);//0x00 0x00 ...

//now calculate tcp checksum
	int tcpchk_tmp = 32;
	unsigned char *tcp_chk_all = (unsigned char *)malloc(sizeof(unsigned char)*(tcpchk_tmp));
	memcpy(tcp_chk_all, buf_share+26, 8);//src and dst ip
	*(tcp_chk_all+8)=0x00;		//0
	*(tcp_chk_all+9)=0x06;		//tcp
	*(tcp_chk_all+10)=0x00;
	//memcpy(tcp_chk_all+11, buf_share+46, 1);
	*(tcp_chk_all+11)=0x14;		//tcp length
	memcpy(tcp_chk_all+12, testreset+34, 20);

	int Tcp_Checksum=wrapsum(htons(sum32u((unsigned char *)tcp_chk_all, 12+20)));//error
	memcpy(testreset+layer2_len+36,&Tcp_Checksum,2);
	//printf("chksum is %02x %02x\n", testreset+layer2_len+36, testreset+layer2_len+37);

	//pkt_send_body(reset_txring,reset_txring_cur,testreset,layer2_len+40+6);

	free(testreset);
	return 0;
}
#endif

void send_reset()
{
	uint8_t src_mac[6] = {0};
	uint8_t dst_mac[6] = {0};
	uint8_t src_ip[4] = {0};
	uint8_t dst_ip[4] = {0};
	uint8_t src_port[2] = {0};
	uint8_t dst_port[2] = {0};
	uint8_t seq[4] = {0};
	uint8_t ack[4] = {0};
	uint8_t  total_len[2] = {0};
	uint32_t payload_len = 0;
	uint32_t tcp_checksum_len = 0;
	uint8_t tcp_head_len = 0;
	uint8_t tcp_flag = 0;
	uint8_t ip_head_len = 0;

	ip_header reset_ip_hdr;
	tcp_header reset_tcp_hdr;
	tcp_psd_header reset_psd_hdr;

	memset(&reset_ip_hdr, 0, sizeof(ip_header));
	memset(&reset_tcp_hdr, 0, sizeof(tcp_header));
	memset(&reset_psd_hdr, 0, sizeof(tcp_psd_header));
	memset(reset_packet, 0, 54);

	reset_ip_hdr.Version  = 4;
	reset_ip_hdr.TTL = 128;
	reset_ip_hdr.HdrLength = 5;
	//reset_ip_hdr.Checksum = 0;
	reset_ip_hdr.Length = htons(40);
	reset_ip_hdr.Protocol = IPPROTO_TCP;
	reset_ip_hdr.Id = ntohs(0xDEAD);
	reset_ip_hdr.Fragment = ntohs(0x4000);
	//reset_ip_hdr.TOS = 0;

	reset_tcp_hdr.Ack = 1;
	reset_tcp_hdr.Rst = 1;
	reset_tcp_hdr.HdrLength = 5;

	reset_psd_hdr.protocol = IPPROTO_TCP;
	reset_psd_hdr.len = htons(20);
	//reset_psd_hdr.zero = 0;

	memcpy(dst_mac, buf_share, 6);  //目的mac
	memcpy(src_mac, buf_share + 6, 6);  //源mac
	memcpy(src_ip, buf_share + layer1_len + 12, 4);
	memcpy(dst_ip, buf_share + layer1_len + 16, 4);
	memcpy(seq, buf_share + 38,  4);
	memcpy(ack, buf_share + 42, 4);
	memcpy(total_len, buf_share + 16, 2);
	memcpy(src_port, buf_share + 34, 2);
	memcpy(dst_port, buf_share + 36, 2);
	memcpy(&ip_head_len, buf_share + 14, 1);
	memcpy(&tcp_head_len, buf_share + 46, 1);
	memcpy(&tcp_flag, buf_share + 47, 1);

	reset_ip_hdr.SrcAddr = (dst_ip[3] << 24) + (dst_ip[2] << 16) + (dst_ip[1] << 8)+ dst_ip[0];
	reset_ip_hdr.DstAddr = (src_ip[3] << 24) + (src_ip[2] << 16) + (src_ip[1] << 8) + src_ip[0];
	reset_ip_hdr.Checksum = checksum(NULL, 0, &reset_ip_hdr, reset_ip_hdr.HdrLength * sizeof(uint32_t)); 

	reset_psd_hdr.src_ip = reset_ip_hdr.SrcAddr;
	reset_psd_hdr.dst_ip = reset_ip_hdr.DstAddr;

	ip_head_len = (ip_head_len	& 0x0f) * 4;
	tcp_head_len = (tcp_head_len >> 4) * 4;
	payload_len = ((total_len[0] << 8) + total_len[1]) - ip_head_len - tcp_head_len;
	//payload_len = ((total_len[1] << 8) + total_len[0]) - 40;
	//tcp_checksum_len = payload_len + reset_tcp_hdr.HdrLength * sizeof(uint32_t);
	reset_tcp_hdr.SrcPort = (dst_port[1] << 8) + dst_port[0];
	reset_tcp_hdr.DstPort = (src_port[1] << 8) + src_port[0];
	reset_tcp_hdr.SeqNum = (ack[3] << 24) + (ack[2] << 16) + (ack[1] << 8) + ack[0];
	if(tcp_flag & 0x02)
		reset_tcp_hdr.AckNum = htonl(((seq[0] << 24) + (seq[1] <<  16) + (seq[2] << 8) + seq[3]) + 1);
	else
		reset_tcp_hdr.AckNum = htonl(((seq[0] << 24) + (seq[1] <<  16) + (seq[2] << 8) + seq[3]) + payload_len);
	
	reset_tcp_hdr.Checksum = checksum(&reset_psd_hdr, sizeof(tcp_psd_header), &reset_tcp_hdr, reset_tcp_hdr.HdrLength * sizeof(uint32_t));

	memcpy(reset_packet, src_mac, 6);
	memcpy(reset_packet + 6, dst_mac, 6);
	reset_packet[12] = 0x08;
	reset_packet[13] = 0x00;
	//memcpy(reset_packet + 12, 0x0800, 2);
	memcpy(reset_packet + 14, &reset_ip_hdr, 20);
	memcpy(reset_packet + 34, &reset_tcp_hdr, 20);

	for(int i = 0; i < 54; i++){
		if((i % 8)  == 0)
			printf("\n");
		printf("%02x ", reset_packet[i]);
	}
	printf("\n");

	return;
	//pkt_send_body(reset_txring,reset_txring_cur,reset_packet, 14 + 40);
}

void replace_request_data(char *policy_data, int policy_len)
{
	uint8_t src_ip[4] = {0};
	uint8_t dst_ip[4] = {0};
	uint8_t total_len[2] = {0};
	uint16_t payload_len = 0;
	//uint8_t ttl = 0;
	//uint16_t check_sum = 0;
	uint8_t tcp_head_len = 0;
	uint8_t ip_head_len = 0;
	uint16_t check_sum_len = 0;
	uint16_t tcp_check_sum = 0;
	int cnt = 0;
	tcp_psd_header reset_psd_hdr;
	int replace = 0;

	memset(&reset_psd_hdr, 0, sizeof(tcp_psd_header));

	memcpy(src_ip, buf_share + layer1_len + 12, 4);
	memcpy(dst_ip, buf_share + layer1_len + 16, 4);
	memcpy(total_len, buf_share+ 16, 2);
	memcpy(&ip_head_len, buf_share + 14, 1);
	memcpy(&tcp_head_len, buf_share + 46, 1);

/*
	buf_share[22] -= 1;                                                          // TTL减1
	memset(buf_share + 24, 0, 2);                                        //  校验和清0
	check_sum = checksum(NULL, 0, buf_share + 14, 20);  // 重新计算校验和
	buf_share[24] = (uint8_t)(check_sum & 0x00ff);
	buf_share[25] = (uint8_t)((check_sum >> 8) & 0x00ff);
*/
	ip_head_len = (ip_head_len	& 0x0f) * 4;
	tcp_head_len = (tcp_head_len >> 4) * 4;
	payload_len = (total_len[0] << 8) + total_len[1] - ip_head_len - tcp_head_len;
	check_sum_len = payload_len + tcp_head_len;

	reset_psd_hdr.protocol = IPPROTO_TCP;
	reset_psd_hdr.len = htons(check_sum_len);
	reset_psd_hdr.src_ip = (src_ip[3] << 24) + (src_ip[2] << 16) + (src_ip[1] << 8) + src_ip[0];
	reset_psd_hdr.dst_ip = (dst_ip[3] << 24) + (dst_ip[2] << 16) + (dst_ip[1] << 8)+ dst_ip[0];

	for(int i = 0; i < payload_len; i++) {
		if(buf_share[layer1_len + layer2_ip_len + layer3_tcp_len + i] == policy_data[0]) {
			cnt++;
			for(int j = 1; j < policy_len; j++) {
				if(buf_share[layer1_len + layer2_ip_len + layer3_tcp_len + i + j] == policy_data[j]) {
					cnt++;
				}
			}
			if(cnt == policy_len) {
				//buf_share[54 + i] = 0x31;
				buf_share[access_info.sql_position] = 0x31;
				replace = 1;
				break;
			}
			cnt = 0;
		}
	}

	if(replace) {
		memset(buf_share + layer1_len + ip_head_len + 16, 0, 2);                                        //  tcp校验和清0
		tcp_check_sum = checksum(&reset_psd_hdr, sizeof(reset_psd_hdr), buf_share + layer1_len + ip_head_len, check_sum_len);
		buf_share[50] = (uint8_t)(tcp_check_sum & 0x00ff);
		buf_share[51] = (uint8_t)((tcp_check_sum >> 8) & 0x00ff);
		printf("方向1数据包替换内容，重新计算校验和为: %02x%02x\n", buf_share[50], buf_share[51]);

		for (int i = 0; i < payload_len + ip_head_len + tcp_head_len + 14; i++) {
			if (i % 16 == 0)
				printf("\n");
			printf("%02x ", buf_share[i]);
		}
		printf("\n\n");
	}
	//pkt_send_body(reset_txring,reset_txring_cur,buf_share1, 14 + (total_len[0] << 8) + total_len[1] );
}

int replace_reponse_data(p_replace_info info)
{
	uint8_t src_ip[4] = {0};
	uint8_t dst_ip[4] = {0};
	uint8_t total_len[2] = {0};
	uint16_t payload_len = 0;
	//uint8_t ttl = 0;
	//uint16_t check_sum = 0;
	uint8_t tcp_head_len = 0;
	uint8_t ip_head_len = 0;
	uint16_t check_sum_len = 0;
	uint16_t tcp_check_sum = 0;
	int cnt = 0;
	int reset_flag = 0;
	tcp_psd_header reset_psd_hdr;
	int replace = 1;

	memset(&reset_psd_hdr, 0, sizeof(tcp_psd_header));

	memcpy(src_ip, buf_share + layer1_len + 12, 4);
	memcpy(dst_ip, buf_share + layer1_len + 16, 4);
	memcpy(total_len, buf_share+ 16, 2);
	memcpy(&ip_head_len, buf_share + 14, 1);
	memcpy(&tcp_head_len, buf_share + 46, 1);
	ip_head_len = (ip_head_len	& 0x0f) * 4;
	tcp_head_len = (tcp_head_len >> 4) * 4;
	payload_len = (total_len[0] << 8) + total_len[1] - ip_head_len - tcp_head_len;
	check_sum_len = payload_len + tcp_head_len;

	reset_psd_hdr.protocol = IPPROTO_TCP;
	reset_psd_hdr.len = htons(check_sum_len);
	reset_psd_hdr.src_ip = (src_ip[3] << 24) + (src_ip[2] << 16) + (src_ip[1] << 8) + src_ip[0];
	reset_psd_hdr.dst_ip = (dst_ip[3] << 24) + (dst_ip[2] << 16) + (dst_ip[1] << 8) + dst_ip[0];

	for(int i = 0; info->value_pos[i] > 0; i++) {
		for(int j = 0; j < info->value_len[i]; j++) {
			buf_share[info->value_pos[i] + j] = info->mask_name[i][j];
		}
	}

	if(replace) {
		memset(buf_share + layer1_len + ip_head_len + 16, 0, 2);                                        //  tcp校验和清0
		tcp_check_sum = checksum(&reset_psd_hdr, sizeof(reset_psd_hdr), buf_share + layer1_len + ip_head_len, check_sum_len);
		buf_share[50] = (uint8_t)(tcp_check_sum & 0x00ff);
		buf_share[51] = (uint8_t)((tcp_check_sum >> 8) & 0x00ff);
		printf("方向2数据包替换内容，重新计算校验和为: %02x%02x\n", buf_share[50], buf_share[51]);
	}

	for (int i = 0; i < payload_len + ip_head_len + tcp_head_len + 14; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf_share[i]);
		/*
		if (isprint(buf_share[i]))
			putchar(buf_share[i]);
		else
			putchar('.');
		*/
	}
	printf("\n\n");

	return reset_flag;
	//pkt_send_body(reset_txring,reset_txring_cur,buf_share,layer1_len+ (total_len[0] << 8) + total_len[1] );
}

void find_value(char *value, int value_len, char *mask, p_replace_info info)
{
	uint8_t total_len[2] = {0};
	uint16_t payload_len = 0;
	uint8_t tcp_head_len = 0;
	uint8_t ip_head_len = 0;
	int cnt = 0;

	if(info->index == 100)
		return;                                       //防止数组溢出，检查数组下标。

	memcpy(total_len, buf_share+ 16, 2);
	memcpy(&ip_head_len, buf_share + 14, 1);
	memcpy(&tcp_head_len, buf_share + 46, 1);
	ip_head_len = (ip_head_len	& 0x0f) * 4;
	tcp_head_len = (tcp_head_len >> 4) * 4;
	payload_len = (total_len[0] << 8) + total_len[1] - ip_head_len - tcp_head_len;
	
	for(int i = 0; i < payload_len; i++) {
		if(buf_share[ip_head_len + tcp_head_len + 14 + i] == value[0]) {
			cnt++;
			for(int j = 1; j < value_len; j++) {
				if(buf_share[ip_head_len + tcp_head_len + 14 + i + j] == value[j]) {
					cnt++;
				}
			}
			if(cnt == value_len) {
				info->value_pos[info->index] = ip_head_len + tcp_head_len + 14 + i;
				info->value_len[info->index] = value_len;
				memcpy(info->mask_name[info->index], mask, value_len);
				info->index++;
			}
			cnt = 0;
		}
	}
}

#if 0
int replace_reponse_data(char *value, char *mask, int value_len)
{
	uint8_t src_ip[4] = {0};
	uint8_t dst_ip[4] = {0};
	uint8_t total_len[2] = {0};
	uint16_t payload_len = 0;
	//uint8_t ttl = 0;
	//uint16_t check_sum = 0;
	uint8_t tcp_head_len = 0;
	uint8_t ip_head_len = 0;
	uint16_t check_sum_len = 0;
	uint16_t tcp_check_sum = 0;
	int cnt = 0;
	int reset_flag = 0;
	tcp_psd_header reset_psd_hdr;
	int replace = 0;

	memset(&reset_psd_hdr, 0, sizeof(tcp_psd_header));
/*
	buf_share[22] -= 1;                                                          // TTL减1
	memset(buf_share + 24, 0, 2);                                         //  校验和清0
	check_sum = checksum(NULL, 0, buf_share + 14, 20);   // 重新计算校验和
	buf_share[24] = (uint8_t)(check_sum & 0x00ff);
	buf_share[25] = (uint8_t)((check_sum >> 8) & 0x00ff);
*/
	memcpy(src_ip, buf_share + layer1_len + 12, 4);
	memcpy(dst_ip, buf_share + layer1_len + 16, 4);
	memcpy(total_len, buf_share+ 16, 2);
	memcpy(&ip_head_len, buf_share + 14, 1);
	memcpy(&tcp_head_len, buf_share + 46, 1);
	ip_head_len = (ip_head_len	& 0x0f) * 4;
	tcp_head_len = (tcp_head_len >> 4) * 4;
	payload_len = (total_len[0] << 8) + total_len[1] - ip_head_len - tcp_head_len;
	check_sum_len = payload_len + tcp_head_len;

	reset_psd_hdr.protocol = IPPROTO_TCP;
	reset_psd_hdr.len = htons(check_sum_len);
	reset_psd_hdr.src_ip = (src_ip[3] << 24) + (src_ip[2] << 16) + (src_ip[1] << 8) + src_ip[0];
	reset_psd_hdr.dst_ip = (dst_ip[3] << 24) + (dst_ip[2] << 16) + (dst_ip[1] << 8)+ dst_ip[0];

	for(int i = 0; i < payload_len; i++) {
		if(buf_share[ip_head_len + tcp_head_len + 14 + i] == value[0]) {
			cnt++;
			for(int j = 1; j < value_len; j++) {
				if(buf_share[ip_head_len + tcp_head_len + 14 + i + j] == value[j]) {
					cnt++;
				}
			}
			if(cnt == value_len) {
				for(int j = 0; j < value_len; j++) {
					buf_share[ip_head_len + tcp_head_len + 14 + i + j] = mask[j];
				}
				reset_flag = 2;
				replace = 1;
			}
			cnt = 0;
		}
	}

	if(replace) {
		memset(buf_share + layer1_len + ip_head_len + 16, 0, 2);                                        //  tcp校验和清0
		tcp_check_sum = checksum(&reset_psd_hdr, sizeof(reset_psd_hdr), buf_share + layer1_len + ip_head_len, check_sum_len);
		buf_share[50] = (uint8_t)(tcp_check_sum & 0x00ff);
		buf_share[51] = (uint8_t)((tcp_check_sum >> 8) & 0x00ff);
		printf("方向2数据包替换内容，重新计算校验和为: %02x%02x\n", buf_share[50], buf_share[51]);

		for (int i = 0; i < payload_len + ip_head_len + tcp_head_len + 14; i++) {
			if (i % 16 == 0) 
				printf("\n");
			printf("%02x ", buf_share[i]);
		}
		printf("\n\n");
	}

	return reset_flag;
	//pkt_send_body(reset_txring,reset_txring_cur,buf_share,layer1_len+ (total_len[0] << 8) + total_len[1] );
}
#endif 