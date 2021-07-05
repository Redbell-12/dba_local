#include <poll.h>
#include <ctype.h>
#include <math.h>
#include <pcap.h>
#include <pcre.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <unistd.h>
#include "head.h"
#include "headfile/find_str/find_str.h"

#ifndef __DEFINE_H__
#define __DEFINE_H__


typedef struct access_ctl_info access_ctl_info_struct;
struct access_ctl_info access_info;

typedef struct {
	int a;
	char *s;
} intchar_t;

typedef struct policy_log_struct {
	char bname[3001];
	struct policy_log_struct *next, *prev;
} policy_log_struct;

typedef struct dba_policy_struct {
	int id;
	char uuid[37];
	char key_name[11];
	char key_ipp[13];
	int log_type;
	int action;
	int str_len;
	int reset_flag;
	pcre *re;
	char re_char[2001];
	char replace[2001];
	struct dba_policy_struct *next, *prev;
} dba_policy_struct;
 
struct my_tcptable_struct {
	char hexname[36];          
	unsigned char *tcp_data;
	u_char TCP_BIG_DATA[TCP_WINDOW];
	unsigned char *tcp_head;
	int tcp_num;
	int tcp_len;
	int tcp_data_len;
	int tcp_data_all_len;
	int tcp_head_len;
	int tcp_state;
	int state;
	unsigned long ack_num;
	unsigned long seq_num;
	unsigned long syn_num;
	unsigned long psh_num;
	unsigned long first_seq;
	int time1;
	int docheck;
	UT_hash_handle hh;         /* makes this structure hashable */
};
struct my_tcptable_struct *my_tcptable=NULL;

typedef struct dba_config_struct {
	int dbip[4];
	int db_port[2];
	char key_ipp[13];
	char userkey[10];
	char security_level[2];
	u_char policy_open[101];
	int db_type;
	int status; //0:reject;1:receive;
	int count_num;
	int if_custom;
	int db_ipp[6];
	int vis_ip1[4];
	int vis_ip2[4];
	int vis_ip1_int;
	int vis_ip2_int;
	char custom_char[100];
	pcre *cus;
	struct dba_config_struct *next, *prev;
} dba_config_struct;

typedef struct access_rule_struct {
	char db_ipport[13];
	int db_type;
	int acc_type;
	char user_name[100];
	pcre *user_name_pcre;
	char db_name[100];
	pcre *db_name_pcre;
	char table_name[100];
	pcre *table_name_pcre;
	int client_type;
	char operate_type[OPERATE_TYPE];
	int where;
	int line1;
	int line2;
	struct access_rule_struct *next, *prev;
} access_rule_struct;



typedef struct request_st{
	int flag;//有效位。若为0时，则此项无效
	unsigned int src_ip;
	unsigned short src_port;
	unsigned int dst_ip;
	unsigned short dst_port;
	unsigned int ack_number;
}request_t;



//王楠增加掩码
//===============================================
//在file_config.c中定义
typedef struct value_mask_tag {
	char uuid[37];
	char userkey[11];
	char ip_port[13];
	int db_type;
	int flag;
	int str_len;
	char value[2001];
	char mask[2001];
	struct value_mask_tag *next, *prev;
} value_mask_t, *p_value_mask_t;

extern p_value_mask_t gp_mask_head;
extern p_value_mask_t gp_mask_elt;
extern p_value_mask_t gp_mask_tmp;
//在access_judge.c中定义
typedef struct strategy_info_tag{
	char uuid[37];
	int reset_flag;
}strategy_info_t;

extern strategy_info_t  strategy_info;
//在send_reset.c中定义
//extern uint8_t reset_packet[54] = {0};
extern int visit_rule;
//====================================================


//=============m_pool=============

struct m_pool{
	/*最大的节点有多大*/
	int node_size_max;
	/*最小的节点有多小*/
	int node_size_min;
	/*目前这个池中有多少节点*/
	int node_num;
	/*内存池是一个链表，链中的每个节点就是一个内存块，这里的pool指向链表中的第一个节点*/
	/*链表中的内存块是按其size从小到大顺序排好的，为的是方便查找合适的尺寸的内存块*/
	struct node *pool;
};
struct node{
	int size;
	int using;
	struct node *next;
	char user_area[0];
};
void m_init(struct m_pool *self);
void *m_malloc(struct m_pool *self,int bytes);
int m_free(char *p);
int m_destroy(struct m_pool *self);

//===========m_pool_done===============





dba_config_struct *config_head = NULL; /* important- initialize to NULL! */
dba_config_struct *config_name, *config_elt, *config_tmp, config_etmp;
dba_policy_struct *policy_head = NULL; /* important- initialize to NULL! */
dba_policy_struct *policy_name, *policy_elt, *policy_tmp, policy_etmp, findstr_elt;
policy_log_struct *policy_log_head = NULL; /* important- initialize to NULL! */
policy_log_struct *policy_log_name, *policy_log_elt, *policy_log_tmp, policy_log_etmp;
access_rule_struct *access_head = NULL; /* important- initialize to NULL! */
access_rule_struct *access_name, *access_elt, *access_tmp, access_etmp;
access_ctl_info_struct *access_1, *access_example;

#endif
