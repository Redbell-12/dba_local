#include <stdio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdlib.h>
//#include <stdint.h>
#include <unistd.h>
#include "head.h"



#ifndef _HEAD_C
#define _HEAD_C
int layer2_len=14;
uint8_t *buf_share;
const uint8_t *buf_check_list;
int c1 = 0, c2 = 0;
int layer1_len = 14;
int layer2_ip_len = 20;
int layer3_tcp_len = 20;
int pkt_len_share = 0;
int count_sql = 0;
int bw_count = 0;		//add pthread to cal packet bw
int sql_len = 0;
int is_compress = 0;
char sys_content[2000] = "";	//use in syslog
char pcap_in_list[200][200] = {"\0"};
int count_read_file = 0;
int count_for_main = 0;
char file_name[200] = "\0";
char pcap_config_file[100]="/home/pcap_list.txt";
char delete_blank_line_glo[]="sed -i '/^ *$/d' /home/pcap_list.txt";
int count_a = 0;
char after_replace[TCP_WINDOW] = "\0";
int do_abort = 0;
int Globalaccess_judge_result = 1;
int check_policy_dba_result = 0;
int Save_log_count=0;
int Save_log_time=0;
int ring_len=5000000;
char key_ipp_zero[12]="000000000000";
#endif
