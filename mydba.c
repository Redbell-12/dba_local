/*  
mydba_local v1
can read a pcap file.
next to read list, read all file in a floder.
20200622:
	modi whitelist
	modi check key words
	add oracle, basic.
20200827 in access_judge modi, MAYBE BAD
*/ 
 
#define _GNU_SOURCE
#include <poll.h>
#define NETMAP_WITH_LIBS

#include <ctype.h>
#include <libnetmap.h>
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
#include "net/waf_user.h"

#include "dbf_basic.h"
#include "access_judge.h"
#include "uthash/src/uthash.h"
#include "uthash/src/utlist.h"
#include "uthash/src/utringbuffer.h"



#define IFTRUNK 0/* If have dot1q head */


#include "headfile/interface.h"
#include "headfile/buffer/buffer.h"
#include "headfile/find_str/find_str.h"

#define sql_request 1
#define sql_response 2

#define REDUCE16(_x)	({ uint32_t x = _x;	\
	x = (x & 0xffff) + (x >> 16);		\
	x = (x & 0xffff) + (x >> 16);		\
	x; } )

#define REDUCE32(_x)	({ uint64_t x = _x;	\
	x = (x & 0xffffffff) + (x >> 32);	\
	x = (x & 0xffffffff) + (x >> 32);	\
	x; } )

#define TCP_WINDOW 20000
#define OVECCOUNT 30/* should be a multiple of 3 */
#define OPERATE_TYPE 30

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
	char key_name[11];
	char key_ipp[13];
	int log_type;
	int action;
	int str_len;
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
	//char db_type[2];
	int db_type;
	//char acc_type[2];
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

typedef struct access_ctl_info access_ctl_info_struct;

void intchar_copy(void *_dst, const void *_src) {
	intchar_t *dst = (intchar_t*)_dst, *src = (intchar_t*)_src;
	dst->a = src->a;
	dst->s = src->s ? strdup(src->s) : NULL;
}

void intchar_dtor(void *_elt) {
	intchar_t *elt = (intchar_t*)_elt;
	free(elt->s);
}

unsigned char sum[2]={0};			//两个保存校验和的全局变量
unsigned char Info[30]={0};			//保存实际数据的全局变量

sem_t sem;

pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex2 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex_log = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex_config = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex_policy = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex_access = PTHREAD_MUTEX_INITIALIZER;

UT_ringbuffer *log_ringbuf;
int Save_log_count=0;
int Save_log_time=0;

struct nm_desc *nm_desc1, *nm_desc2;
u_char *buf_share = NULL;
const u_char *buf_check_list;	//alias for const char* buf
u_char *buf_sys;
 
dba_config_struct *config_head = NULL; /* important- initialize to NULL! */
dba_config_struct *config_name, *config_elt, *config_tmp, config_etmp;
dba_policy_struct *policy_head = NULL; /* important- initialize to NULL! */
dba_policy_struct *policy_name, *policy_elt, *policy_tmp, policy_etmp, findstr_elt;
policy_log_struct *policy_log_head = NULL; /* important- initialize to NULL! */
policy_log_struct *policy_log_name, *policy_log_elt, *policy_log_tmp, policy_log_etmp;
access_rule_struct *access_head = NULL; /* important- initialize to NULL! */
access_rule_struct *access_name, *access_elt, *access_tmp, access_etmp;
access_ctl_info_struct *access_1, *access_example;


buffer mysql_buffer, sqlserver_buffer, oracle_buffer, redis_buffer, oracle_buffer, postgres_buffer, sybase_buffer, shentong_buffer;
buffer syslog_buffer;

int c1 = 0, c2 = 0;
int layer1_len = 14;
int layer2_ip_len = 20;
int layer3_tcp_len = 20;
int pkt_len_share;
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

static int do_abort = 0;

intchar_t ic;
int ring_len=5000000;
char key_ipp_zero[12]="000000000000";
UT_icd intchar_icd = {sizeof(intchar_t), NULL, intchar_copy, intchar_dtor};

struct access_ctl_info access_info;

static void
sigint_h(int sig)	//ctrl+c is the signal to stop
{	(void)sig;	/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

int
pkt_queued(struct nmport_d *d, int tx)
{	u_int i, tot = 0;
	if (tx)
	{	for (i = d->first_tx_ring; i <= d->last_tx_ring; i++)
		{	tot += nm_ring_space(NETMAP_TXRING(d->nifp, i));
		}
	}else
	{	for (i = d->first_rx_ring; i <= d->last_rx_ring; i++)
		{	tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
		}
	}
	return tot;
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

void To_Hex(unsigned int  value, char buffer[], int length)
{	unsigned int i=(sizeof(unsigned  int)*2);
	unsigned int temp;
	int j=0;
	while(i--)
	{	temp = (value&(0xf<<(4*i)))>>(4*i);
		if(temp>9)
			buffer[j] = 'A'+temp-10;
		else
			buffer[j] = '0'+temp;
		j++;
	}
	buffer[length] = '\0';
}

static u_int16_t wrapsum(u_int32_t sum)	{
	sum = ~sum & 0xFFFF;	return (htons(sum));
}

static int waf_htoi(char *s)
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

static int waf_htoi2(char *s)
{	int value = 0;
	int c1, c2, c3, c4;
	c1 = ((unsigned char *)s)[0];
	if (isupper(c1))
		c1 = tolower(c1);
	value = 0;
	c2 = ((unsigned char *)s)[1];
	if (isupper(c2))
		c2 = tolower(c2);
	value += (c2 >= '0' && c2 <= '9' ? c2 - '0' : c2 - 'a' + 10) * 256;
	c3 = ((unsigned char *)s)[2];
	if (isupper(c3))
		c3 = tolower(c3);
	value += (c3 >= '0' && c3 <= '9' ? c3 - '0' : c3 - 'a' + 10) * 16;
	c4 = ((unsigned char *)s)[3];
	if (isupper(c4))
		c4 = tolower(c4);
	value += c4 >= '0' && c4 <= '9' ? c4 - '0' : c4 - 'a' + 10;
	return (value);
}

int dba_policy_insert(FILE * pFile){
	printf("insert policy!\n");
	pthread_mutex_lock(&mutex_policy);
	DL_FOREACH_SAFE(policy_head,policy_elt,policy_tmp){
		DL_DELETE(policy_head,policy_elt);
		free(policy_elt);
	}
	char mystring[2000];
	while ( fgets (mystring , 2000 , pFile) != NULL ){
		if(!memcmp(mystring,"[dba_rule_zcp]",13)){
			if ( (policy_name = (dba_policy_struct*)malloc(sizeof(dba_policy_struct))) != NULL){
				if(fgets (mystring , 2000 , pFile) != NULL)
				{	char policy_id[4];
					memcpy(policy_id,mystring+24,3);
					policy_name->id=atoi(policy_id);
					memcpy(policy_name->key_name,mystring,10);
					memcpy(policy_name->key_ipp,mystring+11,12);
					policy_name->log_type=atoi(mystring+29);
					policy_name->action=atoi(mystring+32);
					policy_name->str_len=atoi(mystring+35);
				}
				const char *error;
    				int  erroffset;
				if(fgets (mystring , 2000 , pFile) != NULL)
				{	mystring[strlen(mystring)-1]=0x00;
					memcpy(policy_name->re_char,mystring,2000);
					policy_name->re= pcre_compile(policy_name->re_char, 0, &error, &erroffset, NULL);
				}
				if(fgets (mystring , 2000 , pFile) != NULL)
				{	mystring[strlen(mystring)-1]=0x00;
					memcpy(policy_name->replace,mystring,2000);
				}
				DL_APPEND(policy_head, policy_name);		
			}
		}
	}
	pthread_mutex_unlock(&mutex_policy);	
	return 1;
}

void* dba_policy_process()
{	char policy_file[50]="/dev/shm/policy.json";
	int policy_time=0;
	while(1)
	{	FILE * pFile;	
		pFile = fopen (policy_file, "r");
		if (pFile == NULL)	{	perror ("Error opening file");	sleep(1);	continue; }
		struct stat buf;
		int result;
		result =stat(policy_file, &buf );
		if( result != 0 )	{	perror( "error" );	sleep(1);	continue;	}		
		if(policy_time==0)
		{	policy_time=buf.st_mtime;
			dba_policy_insert(pFile);
		}
		if(policy_time==buf.st_mtime)
		{	//printf("nochange!!!\n");
		}
		else
		{	printf("policy change!!!!!\n");
			policy_time=buf.st_mtime;
			dba_policy_insert(pFile);
		}
		fclose(pFile);
		sleep(1);
	}
	return 0;
}

int dba_config_insert(FILE * pFile){
	pthread_mutex_lock(&mutex_config);
	DL_FOREACH_SAFE(config_head,config_elt,config_tmp) {
		DL_DELETE(config_head,config_elt);
		free(config_elt);
	}
	pthread_mutex_unlock(&mutex_config);
	char mystring[501];
	while ( fgets (mystring , 500 , pFile) != NULL )
	{
		if(!memcmp(mystring,"[db_content]",10))
		{	while ( fgets (mystring , 300 , pFile) != NULL )
			{	if(memcmp(mystring,"[/db_content]",10))
				{	if ( (config_name = (dba_config_struct*)malloc(sizeof(dba_config_struct))) != NULL)
					{	const char *error;
    						int  erroffset;
						pthread_mutex_lock(&mutex_config);
						config_name->dbip[0]=(u_char)waf_htoi(mystring);
						config_name->dbip[1]=(u_char)waf_htoi(mystring+2);
						config_name->dbip[2]=(u_char)waf_htoi(mystring+4);
						config_name->dbip[3]=(u_char)waf_htoi(mystring+6);

						config_name->db_port[0]=(u_char)waf_htoi(mystring+8);
						config_name->db_port[1]=(u_char)waf_htoi(mystring+10);
						memcpy(config_name->key_ipp,mystring,12);

						config_name->status=atoi(mystring+13);
						config_name->db_type=atoi(mystring+16);
						config_name->if_custom=atoi(mystring+19);
						

						mystring[strlen(mystring)-1]=0x00;
						memcpy(config_name->custom_char, mystring + 22, 100);
						config_name->cus= pcre_compile(config_name->custom_char, 0, &error, &erroffset, NULL);

						memcpy(config_name->policy_open, mystring+19, 8);
						DL_APPEND(config_head, config_name);
						pthread_mutex_unlock(&mutex_config);
					}
				}
				else{
					break;
				}
			}
		}
		if(!memcmp(mystring,"[db_userkey]",10))
		{	while ( fgets (mystring , 300 , pFile) != NULL )
			{	if(memcmp(mystring,"[/db_userkey]",10))
				{	if ( (config_name = (dba_config_struct*)malloc(sizeof(dba_config_struct))) != NULL)
					{	pthread_mutex_lock(&mutex_config);
						memcpy(config_name->userkey, mystring, 10);
						config_name->status=atoi(mystring+11);

						DL_APPEND(config_head, config_name);
						pthread_mutex_unlock(&mutex_config);
					}
				}
				else
				{	break;
				}
			}
		}
		if(!memcmp(mystring,"[visit_rule]",10))
		{	while ( fgets (mystring , 300 , pFile) != NULL )
			{	if(memcmp(mystring,"[/visit_rule]",10))
				{	if ( (config_name = (dba_config_struct*)malloc(sizeof(dba_config_struct))) != NULL)
					{	pthread_mutex_lock(&mutex_config);
//		char db_ipp[12];
//		char visit_ip[8];
						//config_name->visit_rule_id = (u_char)waf_htoi(mystring);
						config_name->db_ipp[0]=(u_char)waf_htoi(mystring);
						config_name->db_ipp[1]=(u_char)waf_htoi(mystring+2);
						config_name->db_ipp[2]=(u_char)waf_htoi(mystring+4);
						config_name->db_ipp[3]=(u_char)waf_htoi(mystring+6);
						config_name->db_ipp[4]=(u_char)waf_htoi(mystring+8);
						config_name->db_ipp[5]=(u_char)waf_htoi(mystring+10);

						config_name->vis_ip1[0]=(u_char)waf_htoi(mystring+13);
						config_name->vis_ip1[1]=(u_char)waf_htoi(mystring+15);
						config_name->vis_ip1[2]=(u_char)waf_htoi(mystring+17);
						config_name->vis_ip1[3]=(u_char)waf_htoi(mystring+19);

						config_name->vis_ip2[0]=(u_char)waf_htoi(mystring+22);
						config_name->vis_ip2[1]=(u_char)waf_htoi(mystring+24);
						config_name->vis_ip2[2]=(u_char)waf_htoi(mystring+26);
						config_name->vis_ip2[3]=(u_char)waf_htoi(mystring+28);

						config_name->vis_ip1_int = config_name->vis_ip1[0]*4096 + config_name->vis_ip1[1]*256 + config_name->vis_ip1[2]*16 + config_name->vis_ip1[3]; 
						config_name->vis_ip2_int = config_name->vis_ip2[0]*4096 + config_name->vis_ip2[1]*256 + config_name->vis_ip2[2]*16 + config_name->vis_ip2[3];
						DL_APPEND(config_head, config_name);
						pthread_mutex_unlock(&mutex_config);
											}
				}
				else
				{	break;
				}
			}
		}
	}
	return 1;
}


int access_rule_insert( FILE * pFile ){
	pthread_mutex_lock(&mutex_access);
	DL_FOREACH_SAFE( access_head, access_elt, access_tmp )
	{	DL_DELETE( access_head, access_elt );
		free( access_elt );
	}
	pthread_mutex_unlock(&mutex_access);	
printf("=============acc_rule==================\n");
	int line1_copy, line_n = 0;
	char mystring[501];
	while ( fgets (mystring , 500 , pFile) != NULL )
	{	if(!memcmp(mystring,"[access_rule]",10))
		{	while ( fgets (mystring , 400 , pFile) != NULL )
			{	if(memcmp(mystring,"[/access_rule]",10))
				{	//printf("protect_ip:%s",mystring);
					if ( (access_name = (access_rule_struct*)malloc(sizeof(access_rule_struct))) != NULL)
					{	const char *error;
    						int  erroffset;					
						pthread_mutex_lock(&mutex_access);
						memcpy(access_name->db_ipport, mystring, 12);
						access_name->db_type = atoi(mystring+13);
						access_name->acc_type = atoi(mystring+16);

						printf("db_ipport is %s\n", access_name->db_ipport);
						printf("db_type is %d\n", access_name->db_type);
						printf("acc_type is %d\n", access_name->acc_type);


						if( access_name->acc_type==1 )
						{	memcpy(access_name->user_name, mystring+19, 100);
							printf("user_name is %s\n", access_name->user_name);
							access_name->user_name_pcre= pcre_compile(access_name->user_name, 0, &error, &erroffset, NULL);
						}
						if( access_name->acc_type==2 )
						{	memcpy(access_name->db_name, mystring+19, 100);
							printf("db_name is %s\n", access_name->db_name);
							access_name->db_name_pcre= pcre_compile(access_name->db_name, 0, &error, &erroffset, NULL);
						}
						if( access_name->acc_type==3 )
						{	memcpy(access_name->table_name, mystring+19, 100);
							printf("table_name is %s\n", access_name->table_name);
							access_name->table_name_pcre= pcre_compile(access_name->table_name, 0, &error, &erroffset, NULL);
						}
						if( access_name->acc_type==5 )
						{	access_name->client_type = atoi(mystring+19);
							printf("client_type is %d\n", access_name->client_type);
						}
						if( access_name->acc_type==6 )
						{	int operate_type_count = 0;
							memcpy(access_name->operate_type, mystring+19, 20);
							printf("operate_type is %s\n", access_name->operate_type);
						}
						if( access_name->acc_type==7 )
						{	access_name->where=atoi(mystring+19);
							printf("where is %d\n", access_name->where);
						}
						if( access_name->acc_type==8 )
						{	access_name->line1=atoi(mystring+19);
							printf("line1 is %d\n", access_name->line1);
							line1_copy = access_name->line1;
							while(line1_copy)
							{
								line_n++;
								line1_copy /= 10;
							}
							printf("line_n is %d\n",line_n);
							access_name->line2=atoi(mystring+19+line_n);
							printf("line2 is %d\n", access_name->line2);
						}
				
						DL_APPEND(access_head, access_name);
						pthread_mutex_unlock(&mutex_access);
					}
				}
				else{
					break;
				}
			}

		}
	}
	return 1;
}
 
void* dba_config_process(){
	char config_file[50]="/dev/shm/dba_config.txt";
	int config_time=0;
	while(1)
	{	FILE * pFile;
		pFile = fopen (config_file, "r");
		if (pFile == NULL){	perror ("Error opening file");	}
		struct stat buf;
		int result;
		result =stat(config_file, &buf );
		if( result != 0 ){	perror( "error" );	sleep(1);	continue;	}		
		if(config_time==0)
		{	config_time=buf.st_mtime;
			dba_config_insert(pFile);
		}
		if(config_time==buf.st_mtime)
		{	//printf("nochange!!!\n");
		}
		else
		{	printf("config change!!!!!\n");
			config_time=buf.st_mtime;
			dba_config_insert(pFile);
		}
		fclose (pFile);
		sleep(1);
	}
	return 0;
}

void* access_rule_process(){
	char access_file[50]="/dev/shm/access_rule.txt";
	struct stat buf;
	int result;
	char mystring[501];
	FILE * pFile;
	
	pFile = fopen(access_file, "r");
	if (pFile == NULL){ perror ("Error opening file"); }	
	result = stat(access_file, &buf );
	access_rule_insert( pFile );
	fclose( pFile );
	sleep(1);
	return 0;
}


typedef struct request_st{
	int flag;//有效位。若为0时，则此项无效
	unsigned int src_ip;
	unsigned short src_port;
	unsigned int dst_ip;
	unsigned short dst_port;
	unsigned int ack_number;
}request_t;

static request_t request[100];

static unsigned int ack_i;


int check_if_file( char *line_in_list)
{	int file_result = 0;
	FILE * pFile_tmp;
	pFile_tmp = fopen(line_in_list, "rb");

	if(pFile_tmp == NULL)
	{	//fclose(pFile_tmp);
		return 0;
	}
//	else if (file_result != 0)
	else if(pFile_tmp != NULL)
	{	fclose(pFile_tmp);
		return 1;
	}
	fclose(pFile_tmp);
	return 1;
}

int check_list( const u_char * buf )
{
	int db_type_tmp = 0;
	int direction_tmp = 0;
	int check_custom = 1;
	buf_check_list = buf;
	pthread_mutex_lock(&mutex_config);
	DL_FOREACH(config_head,config_elt)
	{	if (config_elt->status == 1)	//该条生效启用
		{	if (config_elt->db_port[0] == buf_check_list[36] && config_elt->db_port[1] == buf_check_list[37])	//dir == 1
			{	if ( config_elt->dbip[0]==buf_check_list[30] && config_elt->dbip[1]==buf_check_list[31] && config_elt->dbip[2]==buf_check_list[32] && config_elt->dbip[3]==buf_check_list[33] )
				{	switch( config_elt->db_type )
					{
						case 1: db_type_tmp = 3;	//mysql
							break;
						case 2: db_type_tmp = 5;	//mssql
							break;
						case 3: db_type_tmp = 7;	//oracle
							break;
						case 4: db_type_tmp = 11;	//mariadb
							break;
						case 5: db_type_tmp = 13;	//redis
							break;
						case 6: db_type_tmp = 17;	//sybase
							break;
						case 7: db_type_tmp = 19;	//db2
							break;
						case 8: db_type_tmp = 23;	//informix
							break;
						case 9: db_type_tmp = 29;	//shentong
							break;
						default: db_type_tmp = 0;
					}
					if ( config_elt->if_custom == 0 )
					{	check_custom = 1;
					}
					else if ( config_elt->if_custom == 1 )
					{	check_custom = 101;
					}
					direction_tmp = 1;
					pthread_mutex_unlock(&mutex_config);
					return (db_type_tmp * direction_tmp * check_custom);
				}
			}
			else if ( config_elt->db_port[0] == buf_check_list[34] && config_elt->db_port[1] ==buf_check_list[35] )
			{	if ( config_elt->dbip[0]==buf_check_list[26] && config_elt->dbip[1]==buf_check_list[27] && config_elt->dbip[2]==buf_check_list[28] && config_elt->dbip[3]==buf_check_list[29] )
				{	switch( config_elt->db_type )
					{
						case 1: db_type_tmp = 3;
							break;
						case 2: db_type_tmp = 5;
							break;
						case 3: db_type_tmp = 7;
							break;
						case 4: db_type_tmp = 11;	//mariadb
							break;
						case 5: db_type_tmp = 13;	//redis
							break;
						case 6: db_type_tmp = 17;	//sybase
							break;
						case 7: db_type_tmp = 19;	//db2
							break;
						case 8: db_type_tmp = 23;	//informix
							break;
						case 9: db_type_tmp = 29;	//shentong
							break;
						default: db_type_tmp = 0;
					}

					if ( config_elt->if_custom == 0 )
					{	check_custom = 1;
					}
					else if ( config_elt->if_custom == 1 )
					{	check_custom = 101;
					}
					direction_tmp = 2;
					pthread_mutex_unlock(&mutex_config);
					return (db_type_tmp * direction_tmp );
				}
			}
			else
			{	//printf("not in!\n");
				//printf("no match port\n");
			}
		}
	}
	pthread_mutex_unlock(&mutex_config);
	return 0;
}

int check_tcp_rebuild( int dir, int dbtype, int pkt_len_share, long tv_sec, int if_custom)//s_ip+8, s_port+4, flags+2, length+2
{
	char my_ip_port_char[36] = "";
	char str_tmp[5] = "";
	char *rebuild_all_tcp;
	int tcp_rebuild = 0;	//0 means no rebuild, 1 means need rebuild, 2 means can be rebuild and restore.
	int packet_length = 0;			//printf("buf_share+17 is %d\n",*(buf_share+17));
	int data_length = 0;
	int offset = 0;
	int rebuild_inside_len = 0;
	int tcp_len_tmp[4];
	int ifack, ifpsh, ifsyn, iffin;
	int bad_visit = 10;
	int visit_ip_int = 0;
	//int data_add = 0;	//for oracle, different type of length
	unsigned long before_ack = 0;
	unsigned long first_inside_seq = 0;
	unsigned int *seq_num, *ack_num;
	unsigned int before_length = 0;
	char db_ip_port[12] = "\0";
	char visit_ip[8] = "\0";
	u_char db_mac[6] = "\0";
	u_char visit_mac[6] = "\0";


	struct my_tcptable_struct *str_add, *str_find1;
	
	packet_length = *(buf_share+16) * 256 + *(buf_share+17);

	sprintf(str_tmp, "%d", buf_share[26]);
	strcat(my_ip_port_char, str_tmp);
	sprintf(str_tmp, "%d", buf_share[27]);
	strcat(my_ip_port_char, str_tmp);
	sprintf(str_tmp, "%d", buf_share[28]);
	strcat(my_ip_port_char, str_tmp);
	sprintf(str_tmp, "%d", buf_share[29]);
	strcat(my_ip_port_char, str_tmp);		//sip done
	sprintf(str_tmp, "%d", buf_share[30]);
	strcat(my_ip_port_char, str_tmp);
	sprintf(str_tmp, "%d", buf_share[31]);
	strcat(my_ip_port_char, str_tmp);
	sprintf(str_tmp, "%d", buf_share[32]);
	strcat(my_ip_port_char, str_tmp);
	sprintf(str_tmp, "%d", buf_share[33]);
	strcat(my_ip_port_char, str_tmp);		//dip done
	sprintf(str_tmp, "%d", buf_share[34]*256 + buf_share[35]);
	strcat(my_ip_port_char, str_tmp);		//sport done
	sprintf(str_tmp, "%d", buf_share[36]*256 + buf_share[37]);
	strcat(my_ip_port_char, str_tmp);		//dport done
	
	tcp_len_tmp[0] = (buf_share[layer1_len+32] >> (9-1 - 1)) & 1;
	tcp_len_tmp[1] = (buf_share[layer1_len+32] >> (9-2 - 1)) & 1;
	tcp_len_tmp[2] = (buf_share[layer1_len+32] >> (9-3 - 1)) & 1;
	tcp_len_tmp[3] = (buf_share[layer1_len+32] >> (9-4 - 1)) & 1;
	layer3_tcp_len = (tcp_len_tmp[0]*8 + tcp_len_tmp[1]*4 + tcp_len_tmp[2]*2 + tcp_len_tmp[3]) * 4;		//real tcp header length
	data_length = packet_length - layer2_ip_len - layer3_tcp_len;
	if (data_length <= 0)
		return tcp_rebuild;
	ifack= (buf_share[layer1_len+33] >> (9-4 - 1)) & 1;
	ifpsh= (buf_share[layer1_len+33] >> (9-5 - 1)) & 1;
	ifsyn= (buf_share[layer1_len+33] >> (9-7 - 1)) & 1;
	iffin= (buf_share[layer1_len+33] >> (9-8 - 1)) & 1;

	seq_num = (unsigned int *)(buf_share+layer1_len+24);	//modi define 20200529
	ack_num = (unsigned int *)(buf_share+layer1_len+28);	//modi define 20200529
	if (ifack == 1 && ifsyn == 0 && dir == 2)	//from db to visitor
	{
printf("dir is 2\n");
		memcpy(db_mac, buf_share+6, 6);
		memcpy(visit_mac, buf_share, 6);

		if ( *(buf_share + 5) == 0x00 && (dbtype == 1||dbtype == 4) )	{	//printf("OK packet---------------------------------------\n");
			return tcp_rebuild;
		}
		HASH_FIND_STR(my_tcptable, my_ip_port_char, str_find1);

		if(!str_find1)	//not find
		{	//printf("new packet\n");
			str_add = (struct my_tcptable_struct*)malloc(sizeof(struct my_tcptable_struct));

			memset(str_add->TCP_BIG_DATA, 0x00, TCP_WINDOW);
			memcpy(str_add->hexname, my_ip_port_char, 36);

			pthread_mutex_lock(&mutex);
			str_add->seq_num = htonl(*seq_num);
			str_add->ack_num = htonl(*ack_num);
			str_add->first_seq = str_add->seq_num;
			str_add->tcp_data_len = str_add->seq_num - str_add->first_seq + data_length;
			pthread_mutex_unlock(&mutex);

			if (data_length == 0)	{
				return tcp_rebuild;
			}
			memcpy(str_add->TCP_BIG_DATA, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);
			//copy data part to TCP_BIG_DATA

			HASH_ADD_STR( my_tcptable, hexname, str_add );
			if ( *(buf_share + pkt_len_share - 5) == 0xfe && (dbtype == 1||dbtype == 4) )	//mysql use 0xfe for end
			{	//dbtype = 1;//this is a min version, both 1 and 4 use mysql protocol
				if (data_length < 4)	{
					HASH_DEL( my_tcptable, str_add );	free(str_add);
					return tcp_rebuild;
				}
				else
				{	proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
					HASH_DEL( my_tcptable, str_add );	free(str_add);
					return tcp_rebuild;
				}
			}
			else if ( *(buf_share + pkt_len_share - 13) == 0xfd && *(buf_share + pkt_len_share - 1) == 0x00 && *(buf_share + pkt_len_share - 2) == 0x00 && dbtype == 2 )	//mssql use 0xfd for end
			{	if (data_length < 8)
				{	HASH_DEL( my_tcptable, str_add );	free(str_add);
					return tcp_rebuild;
				}
				else
				{	proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
					HASH_DEL( my_tcptable, str_add );	free(str_add);
					return tcp_rebuild;
				}
			}
			else if ( dbtype == 3 )	//mssql use 0xfd for end
			{	if (data_length < 8)
				{	HASH_DEL( my_tcptable, str_add );	free(str_add);
					return tcp_rebuild;
				}
				else
				{	proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
					HASH_DEL( my_tcptable, str_add );	free(str_add);
					return tcp_rebuild;
				}
			}
			else if ( *(buf_share + pkt_len_share - 1) == 0x00 && dbtype == 9 )	//shentong use 0x00 for end
			{	if (data_length < 8)
				{	HASH_DEL( my_tcptable, str_add );	free(str_add);
					return tcp_rebuild;
				}
				else
				{	proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
					printf("aft shentong_aya\n\n");	
					HASH_DEL( my_tcptable, str_add );	free(str_add);
					return tcp_rebuild;
				}
			}
		}

		else if (str_find1)	//find it!
		{	//printf("find before\n");
			before_ack = str_find1->ack_num;
			before_length = str_find1->tcp_data_len;
			first_inside_seq = str_find1->first_seq;

			if (data_length == 0)
			{	HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
				return tcp_rebuild;
			}
			if (htonl(*ack_num) == before_ack)
			{	offset = htonl(*seq_num) - first_inside_seq;
				if(offset <= 0)
					offset = abs(offset);
				before_length = offset + data_length;
				if (before_length > TCP_WINDOW)
				{	//printf("++++++++++++++++++++++++++++out of range\n");
					HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
					return tcp_rebuild;
				}
				memcpy(str_find1->TCP_BIG_DATA + offset, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);

				str_find1->seq_num = htonl(*seq_num);
				if ( *(buf_share + pkt_len_share - 5)==0xfe && (dbtype == 1||dbtype == 4) )
				{	//dbtype = 1;	//this is a min version, both 1 and 4 use mysql protocol
					if (before_length < 4)
					{	HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
						return tcp_rebuild;
					}
					else
					{	proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, before_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
						return tcp_rebuild;
					}
				}
				else if ( *(buf_share + pkt_len_share - 13)==0xfe && dbtype == 2 )
				{	if (before_length < 8)
					{	HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
						return tcp_rebuild;
					}
					else
					{	proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, before_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
						return tcp_rebuild;
					}
				}
				else if ( dbtype == 3 )
				{	if (before_length < 8)
					{	HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
						return tcp_rebuild;
					}
					else
					{	proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, before_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
						return tcp_rebuild;
					}
				}
				else if ( *(buf_share + pkt_len_share - 1)==0x00 && dbtype == 9 )
				{	if (before_length < 8)
					{	HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
						return tcp_rebuild;
					}
					else
					{	proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, before_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
						return tcp_rebuild;
					}
				}
			}
			else if (htonl(*ack_num) != before_ack)
			{	HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
				str_add = (struct my_tcptable_struct*)malloc(sizeof(struct my_tcptable_struct));

				memset(str_add->TCP_BIG_DATA, 0x20, TCP_WINDOW);
				memcpy(str_add->hexname, my_ip_port_char, 36);
				pthread_mutex_lock(&mutex);
				str_add->seq_num = htonl(*seq_num);
				str_add->ack_num = htonl(*ack_num);
				str_add->first_seq = str_add->seq_num;
				str_add->tcp_data_len = str_add->seq_num - str_add->first_seq + data_length;
				pthread_mutex_unlock(&mutex);
				if (data_length == 0) {
					return tcp_rebuild;	//already del hash
				}
				memcpy(str_add->TCP_BIG_DATA, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);

				HASH_ADD_STR( my_tcptable, hexname, str_add );

				if ( *(buf_share + pkt_len_share - 5) == 0xfe && (dbtype == 1||dbtype == 4) )	//mysql use 0xfe for end
				{	if (data_length < 4)
					{	HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
					else
					{	proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
				}
				else if ( *(buf_share + pkt_len_share - 13) == 0xfd  && *(buf_share + pkt_len_share - 1) == 0x00 && *(buf_share + pkt_len_share - 2) == 0x00 && dbtype == 2 )
				{	if (data_length < 8)
					{	HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
					else
					{	proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
				}
				else if ( dbtype == 3 )
				{	if (data_length < 8)
					{	HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
					else
					{	proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
				}
				else if ( *(buf_share + pkt_len_share - 1)==0x00 && dbtype == 9 )
				{	if (data_length < 8)
					{	HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
					else
					{	proto_analysis(dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
				}
			}
		}
	} 
	else if (ifack == 1 && ifsyn == 0 && dir == 1)	//visit db
	{
printf("dir is 1\n");
		if (data_length <= 0){
			return tcp_rebuild;	//bad data return
		}

//	add visit ip check

		memcpy(db_mac, buf_share, 6);
		memcpy(visit_mac, buf_share+6, 6);

		pthread_mutex_lock(&mutex_config);
		DL_FOREACH(config_head,config_elt)
		{	//printf("judge\n");
			if (config_elt->db_ipp[4] == buf_check_list[36] && config_elt->db_ipp[5] == buf_check_list[37])
			{	//printf("same db port\n");
				if ( config_elt->db_ipp[0]==buf_check_list[30] && config_elt->db_ipp[1]==buf_check_list[31] && config_elt->db_ipp[2]==buf_check_list[32] && config_elt->db_ipp[3]==buf_check_list[33] )
				{	//printf("same db ip\n");
					visit_ip_int = buf_check_list[26]*4096 + buf_check_list[27]*256 + buf_check_list[28]*16 + buf_check_list[29];
					if ( visit_ip_int >= config_elt->vis_ip1_int && visit_ip_int <= config_elt->vis_ip2_int )
					{	printf("same visit ip\n");
						bad_visit = 0;
					}
				}
				else
					bad_visit = 0;
			}
			else 
				bad_visit = 0;
		} 
		pthread_mutex_unlock(&mutex_config);

		HASH_FIND_STR(my_tcptable, my_ip_port_char, str_find1);
		
		if(!str_find1)	//first packet in this session
		{
//printf("new\n");
			str_add = (struct my_tcptable_struct*)malloc(sizeof(struct my_tcptable_struct));
			memset(str_add->TCP_BIG_DATA, 0x00, TCP_WINDOW);
			memcpy(str_add->hexname, my_ip_port_char, 36);
			pthread_mutex_lock(&mutex);
			str_add->seq_num = htonl(*seq_num);
			str_add->ack_num = htonl(*ack_num);
			str_add->first_seq = str_add->seq_num;
			str_add->tcp_data_len = data_length;	//if not the firsrt, should be (str_add->seq_num - str_add->first_seq + data_length)
			pthread_mutex_unlock(&mutex);

			if (str_add->tcp_data_len <= 0)
			{	free(str_add);	//no HASH_ADD, just free
				return tcp_rebuild;	//bad data return
			}
			memcpy(str_add->TCP_BIG_DATA, buf_share + layer1_len + layer2_ip_len + layer3_tcp_len, data_length);
			//printf("zcp1\n\n");

			if ( (dbtype == 1||dbtype == 4) )
			{	if (data_length < 4)
				{	free(str_add);	//no HASH_ADD, just free
					return tcp_rebuild;
				}
				else
				{	int real_data_length = *str_add->TCP_BIG_DATA + (*(str_add->TCP_BIG_DATA+1))*256 + (*(str_add->TCP_BIG_DATA+2))*66536;
					str_add->tcp_data_all_len = real_data_length;
					HASH_ADD_STR( my_tcptable, hexname, str_add );

					if (str_add->tcp_data_all_len > str_add->tcp_data_len)
					{	HASH_DEL( my_tcptable, str_add );	free(str_find1);
						return tcp_rebuild;	//this packet is the first packet, need to rebuild
					}
					proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
	 				if (str_add->tcp_data_all_len == (int)(before_length + str_add->seq_num - first_inside_seq + data_length) )
					{	HASH_DEL( my_tcptable, str_add );	free(str_find1);
						return tcp_rebuild;
					}
				}
			}
			else if ( dbtype == 2 )
			{
				if (data_length < 8)	{
					return tcp_rebuild;
				}
				else
				{	int real_data_length = *(str_add->TCP_BIG_DATA+2)*256 + *(str_add->TCP_BIG_DATA+3);
printf("real_data_length is %d\n", real_data_length);
					str_add->tcp_data_all_len = real_data_length;
					HASH_ADD_STR( my_tcptable, hexname, str_add );
					if (str_add->tcp_data_all_len > str_add->tcp_data_len)
					{	HASH_DEL( my_tcptable, str_add );	free(str_find1);
						return tcp_rebuild;	//this packet is the first packet, need to rebuild
					}

					proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);

					if (str_add->tcp_data_all_len == data_length)
					{	HASH_DEL( my_tcptable, str_add );	free(str_find1);
						return tcp_rebuild;
					}
				}
			}
			else if ( dbtype == 3 )
			{
//printf("oracle\n");
				if (data_length < 8)	{
					return tcp_rebuild;
				}
				else
				{	int real_data_length = *(str_add->TCP_BIG_DATA)*256 + *(str_add->TCP_BIG_DATA+1);
					if(real_data_length == 0)
					{
						real_data_length = *(str_add->TCP_BIG_DATA+2)*256 + *(str_add->TCP_BIG_DATA+3);
						//data_add = 2;
					}
					str_add->tcp_data_all_len = real_data_length;
					//printf("str_add->tcp_data_all_len is %d\n", str_add->tcp_data_all_len);
					//printf("str_add->tcp_data_len is %d\n", str_add->tcp_data_len);	
					HASH_ADD_STR( my_tcptable, hexname, str_add );
					if (str_add->tcp_data_all_len > str_add->tcp_data_len)
					{	HASH_DEL( my_tcptable, str_add );	free(str_find1);
						//printf("wait for next packet\n");
						return tcp_rebuild;	//this packet is the first packet, need to rebuild
					}
					proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);

//printf("after analysis\n");

					if (str_add->tcp_data_all_len == data_length)
					{	HASH_DEL( my_tcptable, str_add );	free(str_find1);
						return tcp_rebuild;
					}
				}
			}
			else if ( dbtype == 9 )		//&& *(buf_share + pkt_len_share)==0x00 
			{	if (*(buf_share + pkt_len_share - 1)==0x00)	{
					str_add->tcp_data_all_len = data_length;
					HASH_ADD_STR( my_tcptable, hexname, str_add );
					proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
					printf("aft shentong_aya\n\n");					
					HASH_DEL( my_tcptable, str_add );	free(str_find1);
					return tcp_rebuild;
				}
			//	else	{
			//		str_add->tcp_data_all_len = data_length;
			//		HASH_ADD_STR( my_tcptable, hexname, str_add );
			//		return tcp_rebuild;	//this packet is the first packet, need to rebuild
			//	}
			}
		}
		else if (str_find1)	//have session before
		{
//printf("find?\n");
			before_ack = str_find1->ack_num;
			before_length = str_find1->tcp_data_len;
			first_inside_seq = str_find1->first_seq;
			if (htonl(*ack_num) == before_ack)
			{	if (dbtype == 2)
				{	//when rebuild, should delete the mssql header
					data_length = data_length - 8;
				}
				offset = htonl(*seq_num) - first_inside_seq;
				if(offset < 0)
					offset = abs(offset);

				if (offset + data_length > TCP_WINDOW)
				{//	printf("++++++++++++++++++++++++++++out of range\n");
					return tcp_rebuild;
				}
				memcpy(str_find1->TCP_BIG_DATA + offset, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);

				str_find1->seq_num = htonl(*seq_num);
				if ( str_find1->tcp_data_all_len = before_length + str_find1->seq_num - first_inside_seq + data_length )
				{	if ( (dbtype == 1||dbtype == 4) && (offset + data_length >= 4 ) ) {
						proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share,tv_sec, buf_share+38, buf_share+42, buf_share, str_find1->tcp_data_all_len, bad_visit, if_custom);
					}
					if ( dbtype == 2 && (offset + data_length >= 8 ) ) {
						proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, str_find1->tcp_data_all_len, bad_visit, if_custom);
					}
					if ( dbtype == 3 && (offset + data_length >= 8 ) ) {
						proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, str_find1->tcp_data_all_len, bad_visit, if_custom);
					}
					if ( dbtype == 9 && (offset + data_length >= 8 ) ) {
						proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, str_find1->tcp_data_all_len, bad_visit, if_custom);
					}
					HASH_DEL( my_tcptable, str_find1 );	free(str_find1);
					return tcp_rebuild;
				}
			}
			else if (htonl(*ack_num) > before_ack)
			{
				HASH_DEL( my_tcptable, str_find1 );	free(str_find1);

				str_add = (struct my_tcptable_struct*)malloc(sizeof(struct my_tcptable_struct));
				memset(str_add->TCP_BIG_DATA, 0x20, TCP_WINDOW);
				memcpy(str_add->hexname, my_ip_port_char, 36);

				pthread_mutex_lock(&mutex);
				str_add->seq_num = htonl(*seq_num);
				str_add->ack_num = htonl(*ack_num);
				str_add->first_seq = str_add->seq_num;
				str_add->tcp_data_len = str_add->seq_num - str_add->first_seq + data_length;
				pthread_mutex_unlock(&mutex);

				if (data_length == 0)
				{	free(str_add);
					return tcp_rebuild;
				}
				memcpy(str_add->TCP_BIG_DATA, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);

				HASH_ADD_STR( my_tcptable, hexname, str_add );
				if (str_add->tcp_data_all_len > str_add->tcp_data_len)
				{	HASH_DEL( my_tcptable, str_add );	free(str_add);
					return tcp_rebuild;	//this packet is the first packet, need to rebuild
				}
				if ( (dbtype == 1||dbtype == 4) )
				{	if (data_length < 4)
					{	HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
					else
					{	proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
						HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
				}
				if ( dbtype == 2 )
				{
					if (data_length < 4)
					{	HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
					else
					{	proto_analysis(dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
						HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
				}
				if ( dbtype == 3 )
				{	if (data_length < 4)
					{	HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
					else
					{	proto_analysis(dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
						HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
				}
				if ( dbtype == 9 )
				{	if (data_length < 4)	{
						return tcp_rebuild;
					}
					else
					{	proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
						HASH_DEL( my_tcptable, str_add );	free(str_add);
						return tcp_rebuild;
					}
				}
			}
		}
	}
	return tcp_rebuild;
}

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * buf)	
{
	int i, dir = 0;
	int check_rebuild_result = 0;
	int dbtype = 0;
	int direction = 0;
	int if_custom = 0;
	int check_custom = 0;
	sql_len = 0;
	buf_share = buf;
	pkt_len_share = pkthdr->caplen;
	if(buf_share[12]==0x08 && buf_share[13]==0x00 && buf_share[23]==0x06) //ipv4 and tcp
	{
		if ( check_list(buf) == 0 ) {
			return;
		}
		else if ( check_list(buf) % 2 == 0 )
		{	count_sql++;
			direction = 2;
			if ( check_list(buf) % 101 == 0 )
			{	if_custom = 1;
				check_custom = check_list(buf)/101;
			}
			else 
			{	if_custom = 0;
				check_custom = check_list(buf);
			}
			
			switch ( check_list(buf) / 2 )
			{
				case 3: dbtype = 1;//mysql
					break;
				case 5: dbtype = 2;//sqlserver
					break;
				case 7: dbtype = 3;//oracle
					break;
				case 11: dbtype = 4;//mariadb
					break;
				case 13: dbtype = 5;//redis
					break;
				case 17: dbtype = 6;//sqlserver
					break;
				case 19: dbtype = 7;//oracle
					break;
				case 23: dbtype = 8;//mariadb
					break;
				case 29: dbtype = 9;//redis
					break;
				default: dbtype = 0;
			}
			check_tcp_rebuild( direction, dbtype, pkt_len_share, pkthdr->ts.tv_sec, 0);
		}
		else if ( check_list(buf) % 2 == 1 )
		{	count_sql++;
			direction = 1;
			if ( check_list(buf) % 101 == 0 )
			{	if_custom = 1;
				check_custom = check_list(buf)/101;
			}
			else 
			{	if_custom = 0;
				check_custom = check_list(buf);
			}
			switch ( check_custom )
			{
				case 3: dbtype = 1;//mysql
					break;
				case 5: dbtype = 2;//sqlserver
					break;
				case 7: dbtype = 3;//oracle
					break;
				case 11: dbtype = 4;//mariadb
					break;
				case 13: dbtype = 5;//redis
					break;
				case 17: dbtype = 6;//sqlserver
					break;
				case 19: dbtype = 7;//oracle
					break;
				case 23: dbtype = 8;//mariadb
					break;
				case 29: dbtype = 9;//redis
					break;
				default: dbtype = 0;
			}
			check_tcp_rebuild( direction, dbtype, pkt_len_share, pkthdr->ts.tv_sec, if_custom);
		}
		else
		{
			count_sql++;
		}
	}
	else if ( buf_share[12]==0x08 && buf_share[13]==0x00 )	//ip packet
	{	if ( buf_share[23]==0x11 && buf_share[36]==0x02 && buf_share[37]==0x02 )	//udp and 514
		{	if ( check_list(buf) == 0 )
			{
			}
			else
			{
			}
		}
	}
}


int check_policy_dba( char *src, char* the_ip_port)
{	int  ovector[OVECCOUNT];
	int  rc, i;
	int log_len=strlen(src);
	pthread_mutex_lock(&mutex_policy);
	DL_FOREACH(policy_head,policy_elt)
	{	if(!memcmp(policy_elt->key_ipp, the_ip_port, 12) || !memcmp(policy_elt->key_ipp,key_ipp_zero,12))
		{	if ( ( rc = pcre_exec(policy_elt->re, NULL, src, strlen(src), 0, 0, ovector, OVECCOUNT)) != PCRE_ERROR_NOMATCH )
			{	printf("policy access system_find_OK!!!!,id:%d,action:%d\n",policy_elt->id,policy_elt->action);
				if (policy_elt->action == 1)
				{	pthread_mutex_unlock(&mutex_policy);
					return policy_elt->id;
				}
				else if (policy_elt->action == 0)
				{	pthread_mutex_unlock(&mutex_policy);
					return policy_elt->action;
				}
			}
			else 
			{	//printf("no match\n");
			}
		}
	}
	pthread_mutex_unlock(&mutex_policy);
	return 0;
}


int check_if_log( char *src, char* the_ip_port)
{	int  ovector[OVECCOUNT];
	int  custom_rc, i;
	int log_len=strlen(src);
	printf("the_ip_port is %s\n", the_ip_port);
	pthread_mutex_lock(&mutex_config);
	DL_FOREACH(config_head,config_elt)
	{	printf("config_elt->key_ipp is %s\n", config_elt->key_ipp);
		printf("config_elt->key_ipp is %s\n", config_elt->key_ipp);
		if(!memcmp(config_elt->key_ipp, the_ip_port, 12))
		{	//printf("p3\n");
			if ( ( custom_rc = pcre_exec(config_elt->cus, NULL, src, strlen(src), 0, 0, ovector, OVECCOUNT)) != PCRE_ERROR_NOMATCH )
			{	printf("config access system_find_OK!!!!,key_ipp:%s,action:%s\n", config_elt->key_ipp, config_elt->custom_char);
				pthread_mutex_unlock(&mutex_config);
				return 0;	//record
			}
			else 
			{	//printf("no match\n");
				pthread_mutex_unlock(&mutex_config);
				return 1;
			}
		}
	}
	pthread_mutex_unlock(&mutex_config);
	return 0;
}

/*access_judge.h
*/


static int process_rings(struct netmap_ring *rxring, struct netmap_ring *txring, u_int limit, const char *msg, u_int bdir)
{	u_int j, k, m = 0;

	if (rxring->flags || txring->flags)
		D("%s rxflags %x txflags %x", msg, rxring->flags, txring->flags);
	j = rxring->head; /* RX */
	k = txring->head; /* TX */
	m = nm_ring_space(rxring);
	if (m < limit)
		limit = m;
	m = nm_ring_space(txring);
	if (m < limit)
		limit = m;
	m = limit;
	while (limit-- > 0)
	{	struct netmap_slot *rs = &rxring->slot[j];
		struct netmap_slot *ts = &txring->slot[k];

//zcp
		if(bdir == 1)	//visitor to db
		{	u_char *buf = (u_char *)NETMAP_BUF(rxring, rxring->slot[j].buf_idx);
			if( (buf[12]==0x08) && (buf[13]==0x00) )
			{	if( buf[23]==0x01 )
				{	printf("dir is 1\n");
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]);
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31]);
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39]);

					printf("source is %d.%d.%d.%d\n", buf[26], buf[27], buf[28], buf[29]);
					printf("desti is %d.%d.%d.%d\n\n", buf[30], buf[31], buf[32], buf[33]);
					
				}
			}

			/* swap packets */
			if (ts->buf_idx < 2 || rs->buf_idx < 2)
			{	RD(5, "wrong index rx[%d] = %d  -> tx[%d] = %d",
					j, rs->buf_idx, k, ts->buf_idx);
				sleep(2);
			}

			/* copy the packet length. */
			if (rs->len > rxring->nr_buf_size)
			{	RD(5, "wrong len %d rx[%d] -> tx[%d]", rs->len, j, k);
				rs->len = 0;
			}
			ts->len = rs->len;

			uint32_t pkt = ts->buf_idx;
			ts->buf_idx = rs->buf_idx;
			rs->buf_idx = pkt;
			/* report the buffer change. */
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
			/* copy the NS_MOREFRAG */
			rs->flags = (rs->flags & ~NS_MOREFRAG) | (ts->flags & NS_MOREFRAG);

			j = nm_ring_next(rxring, j);
			k = nm_ring_next(txring, k);
		}
		
		if(bdir == 2)	//db to visitor
		{	u_char *buf = (u_char *)NETMAP_BUF(rxring, rxring->slot[j].buf_idx);
			if( (buf[12]==0x08) && (buf[13]==0x00) )
			{	if( buf[23]==0x01 )
				{	printf("dir is 2\n");
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]);
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31]);
					printf("%02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x\n", 
						buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39]);

					printf("source is %d.%d.%d.%d\n", buf[26], buf[27], buf[28], buf[29]);
					printf("desti is %d.%d.%d.%d\n\n", buf[30], buf[31], buf[32], buf[33]);
				}
			}
			
			/* swap packets */
			if (ts->buf_idx < 2 || rs->buf_idx < 2)
			{	RD(5, "wrong index rx[%d] = %d  -> tx[%d] = %d",
					j, rs->buf_idx, k, ts->buf_idx);
				sleep(2);
			}
			/* copy the packet length. */
			if (rs->len > rxring->nr_buf_size)
			{	RD(5, "wrong len %d rx[%d] -> tx[%d]", rs->len, j, k);
				rs->len = 0;
			}
			ts->len = rs->len;

			uint32_t pkt = ts->buf_idx;
			ts->buf_idx = rs->buf_idx;
			rs->buf_idx = pkt;
			/* report the buffer change. */
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
			/* copy the NS_MOREFRAG */
			rs->flags = (rs->flags & ~NS_MOREFRAG) | (ts->flags & NS_MOREFRAG);

			j = nm_ring_next(rxring, j);
			k = nm_ring_next(txring, k);
		}
	}
	rxring->head = rxring->cur = j;
	txring->head = txring->cur = k;
	return (m);
}


static int move(struct nmport_d *src, struct nmport_d *dst, u_int limit, u_int bdir)
{
	struct netmap_ring *txring, *rxring;
	u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;
	const char *msg = (src->reg.nr_flags == NR_REG_SW) ? "host->net" : "net->host";
	printf("bdir is %d\n", bdir);
	while (si <= src->last_rx_ring && di <= dst->last_tx_ring)
	{	rxring = NETMAP_RXRING(src->nifp, si);
		txring = NETMAP_TXRING(dst->nifp, di);
		ND("txring %p rxring %p", txring, rxring);
		if (nm_ring_empty(rxring))
		{	si++;
			continue;
		}
		if (nm_ring_empty(txring))
		{	di++;
			continue;
		}
		m += process_rings(rxring, txring, limit, msg, bdir);
	}
	return (m);
}

#if 0
int main(int argc, char *argv[])
{ 
	utringbuffer_new(log_ringbuf,ring_len , &intchar_icd);
	init_buffer( &mysql_buffer );
	init_buffer( &sqlserver_buffer );
	init_buffer( &oracle_buffer );
	init_buffer( &redis_buffer );
	init_buffer( &syslog_buffer );
	init_buffer( &postgres_buffer );
	init_buffer( &sybase_buffer );
	init_buffer( &shentong_buffer );

	char errBuf[PCAP_ERRBUF_SIZE], *devStr;
	pcap_if_t *alldevs;
	int id = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *net_work = argv[1];

	set_timer(5);

	pthread_t dba_policy_process1;
	pthread_create(&dba_policy_process1, NULL, dba_policy_process,NULL);
	pthread_detach(dba_policy_process1);
	
	pthread_t dba_config_process1;
	pthread_create(&dba_config_process1,NULL,dba_config_process,NULL);
	pthread_detach(dba_config_process1);

	pthread_t access_rule_process1;
	pthread_create(&access_rule_process1,NULL,access_rule_process,NULL);
	pthread_detach(access_rule_process1);

	sleep(5);
	//printf("why not printf\n");
	pthread_mutex_lock(&mutex_config);
	DL_FOREACH(config_head,config_elt)
	{	printf("config_elt->dbip:%02x%02x%02x%02x, port:%02x%02x, status:%d, db_type:%d\n", config_elt->dbip[0], config_elt->dbip[1], config_elt->dbip[2], config_elt->dbip[3], config_elt->db_port[0], config_elt->db_port[1], config_elt->status, config_elt->db_type);
		printf("config_name->userkey is %s, config_name->staus is %d\n", config_elt->userkey, config_elt->status);
	}
	pthread_mutex_unlock(&mutex_config);

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{	fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	devStr = net_work;
	if(devStr)
	{	printf("success: device: %s\n", devStr);
	}
	else
	{	printf("error: %s\n", errbuf); 
		exit(1);
	}
	pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
	if(!device)
	{
		printf("error: pcap_open_live(): %s\n", errBuf);
		exit(1);
	}
	struct bpf_program filter;
	//pcap_compile(device, &filter, "dst port 80", 1, 0);
	pcap_compile(device, &filter, "", 1, 0);
	pcap_setfilter(device, &filter);

	pcap_loop(device, -1, getPacket, (u_char*)&id);
	pcap_close(device);

	return 0;
}
#endif


int main(int argc, char **argv)
{
	struct pollfd pollfd[2];
	//int ch;
	u_int burst = 1024, wait_link = 1;
	u_int bdir = 1;
	struct nmport_d *pa = NULL, *pb = NULL;
	char ifa[20] = "netmap:", ifb[20] = "netmap:";
	printf("argc is %d\n", argc);
	fprintf(stderr, "%s built %s %s\n", argv[0], __DATE__, __TIME__);

	utringbuffer_new(log_ringbuf,ring_len , &intchar_icd);
	init_buffer( &mysql_buffer );
	init_buffer( &sqlserver_buffer );
	init_buffer( &oracle_buffer );
	init_buffer( &redis_buffer );
	init_buffer( &syslog_buffer );
	init_buffer( &postgres_buffer );
	init_buffer( &sybase_buffer );
	init_buffer( &shentong_buffer );

	char errBuf[PCAP_ERRBUF_SIZE], *devStr;
	pcap_if_t *alldevs;
	int id = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *net_work = argv[1];

	set_timer(5);

	pthread_t dba_policy_process1;
	pthread_create(&dba_policy_process1, NULL, dba_policy_process,NULL);
	pthread_detach(dba_policy_process1);
	
	pthread_t dba_config_process1;
	pthread_create(&dba_config_process1,NULL,dba_config_process,NULL);
	pthread_detach(dba_config_process1);

	pthread_t access_rule_process1;
	pthread_create(&access_rule_process1,NULL,access_rule_process,NULL);
	pthread_detach(access_rule_process1);

	sleep(5);
	//printf("why not printf\n");
	pthread_mutex_lock(&mutex_config);
	DL_FOREACH(config_head,config_elt)
	{	printf("config_elt->dbip:%02x%02x%02x%02x, port:%02x%02x, status:%d, db_type:%d\n", config_elt->dbip[0], config_elt->dbip[1], config_elt->dbip[2], config_elt->dbip[3], config_elt->db_port[0], config_elt->db_port[1], config_elt->status, config_elt->db_type);
		printf("config_name->userkey is %s, config_name->staus is %d\n", config_elt->userkey, config_elt->status);
	}
	pthread_mutex_unlock(&mutex_config);


	strcat(ifa, argv[1]);
	strcat(ifb, argv[2]);
	pa = nmport_open(ifa);
	pb = nmport_open(ifb);

	if ( (pa == NULL)||(pb == NULL) )
	{	D("cannot open %s or %s\n", ifa, ifb);
		return (1);
	}

	/* setup poll(2) array */
	memset(pollfd, 0, sizeof(pollfd));
	pollfd[0].fd = pa->fd;
	pollfd[1].fd = pb->fd;

	sleep(wait_link);

	/* main loop */
	signal(SIGINT, sigint_h);
	while (!do_abort)
	{
		int n0, n1, ret;
		pollfd[0].events = pollfd[1].events = 0;
		pollfd[0].revents = pollfd[1].revents = 0;
		n0 = pkt_queued(pa, 0);
		n1 = pkt_queued(pb, 0);

#if defined(_WIN32) || defined(BUSYWAIT)
		if (n0)
		{	ioctl(pollfd[1].fd, NIOCTXSYNC, NULL);
			pollfd[1].revents = POLLOUT;
		} else
		{	ioctl(pollfd[0].fd, NIOCRXSYNC, NULL);
		}

		if (n1)
		{	ioctl(pollfd[0].fd, NIOCTXSYNC, NULL);
			pollfd[0].revents = POLLOUT;
		} else
		{	ioctl(pollfd[1].fd, NIOCRXSYNC, NULL);
		}

		ret = 1;
#else
		if (n0)
		{	pollfd[1].events |= POLLOUT;
			bdir = 1;
		} else
		{	pollfd[0].events |= POLLIN;
		}
		if (n1)
		{	pollfd[0].events |= POLLOUT;
			bdir = 2;
		}else
		{	pollfd[1].events |= POLLIN;
		}
		/* poll() also cause kernel to txsync/rxsync the NICs */
		ret = poll(pollfd, 2, 2500);
#endif /* defined(_WIN32) || defined(BUSYWAIT) */

		if (pollfd[0].revents & POLLERR)
		{	struct netmap_ring *rx = NETMAP_RXRING(pa->nifp, pa->cur_rx_ring);
			D("error on fd0, rx [%d,%d,%d)", rx->head, rx->cur, rx->tail);
		}
		if (pollfd[1].revents & POLLERR)
		{	struct netmap_ring *rx = NETMAP_RXRING(pb->nifp, pb->cur_rx_ring);
			D("error on fd1, rx [%d,%d,%d)", rx->head, rx->cur, rx->tail);
		}
		if (pollfd[0].revents & POLLOUT)
			move(pb, pa, burst, bdir);

		if (pollfd[1].revents & POLLOUT)
			move(pa, pb, burst, bdir);
	}
	nmport_close(pb);
	nmport_close(pa);
	return (0);
}
