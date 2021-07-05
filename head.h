#include <stdio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "uthash/src/uthash.h"
#include "uthash/src/utlist.h"
#include "uthash/src/utringbuffer.h"

#ifndef __HEAD_H__
#define __HEAD_H__


#define TCP_WINDOW 20000
#define OVECCOUNT 30/* should be a multiple of 3 */
#define OPERATE_TYPE 30

#define sql_request 1
#define sql_response 2

extern int layer2_len;
extern uint8_t *buf_share;
extern const uint8_t *buf_check_list;
extern int c1, c2;
extern int layer1_len;
extern int layer2_ip_len;
extern int layer3_tcp_len;
extern int pkt_len_share;
extern int count_sql;
extern int bw_count;		//add pthread to cal packet bw
extern int sql_len;
extern int is_compress;
extern char sys_content[2000];	//use in syslog
extern char pcap_in_list[200][200];
extern int count_read_file;
extern int count_for_main;
extern char file_name[200];
extern char pcap_config_file[100];
extern char delete_blank_line_glo[100];
extern int count_a;
extern char after_replace[TCP_WINDOW];
extern int do_abort;
extern int Globalaccess_judge_result;
extern int check_policy_dba_result;
extern int Save_log_count;
extern int Save_log_time;
extern int ring_len;
extern char key_ipp_zero[12];

#endif


#ifndef __PKT_SEND_H__
#define __PKT_SEND_H__
//int pkt_send_body(net_ring *my_txring,uint32_t *my_txring_cur,u_char *buf_tmp,int len);
//int pkt_send_reset_data(net_ring *reset_txring,uint32_t *reset_txring_cur,int reset_option,int tcp_len);
#endif



//#ifndef __PKT_SEND_H__
//#define __PKT_SEND_H__
//int pkt_send_body(net_ring *my_txring,uint32_t *my_txring_cur,u_char *buf_tmp,int len);
//int pkt_send_reset_data(net_ring *reset_txring,uint32_t *reset_txring_cur,int reset_option,int tcp_len);
//#endif

