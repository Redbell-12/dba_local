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
//#include "net/waf_user.h"
#include "send_reset.c"

//#include "access_judge.h"
#include "uthash/src/uthash.h"
#include "uthash/src/utlist.h"
#include "uthash/src/utringbuffer.h"

#define IFTRUNK 0/* If have dot1q head */

#include "headfile/interface.h"
#include "headfile/buffer/buffer.h"
#include "headfile/find_str/find_str.h"
//#include "check_text.h"
//#include "check_text.c"

#include "define.h"
#include "head.h"
#include "head.c"
#include "access_judge.h"
#include "access_judge.c"
#include "file_conf.h"
#include "file_conf.c"
#include "check_tcp_rebuild.h"
#include "check_tcp_rebuild.c"
//#include "check_list.c"
#include "check_list_dba.c"

//#include "m_pool.h"
#include "m_pool.c"

char *outfile_path = "/home/dba_local.txt";
int verbose = 0;



void intchar_copy(void *_dst, const void *_src) {
	intchar_t *dst = (intchar_t*)_dst, *src = (intchar_t*)_src;
	dst->a = src->a;
	dst->s = src->s ? strdup(src->s) : NULL;
}

extern void intchar_dtor(void *_elt) {
	intchar_t *elt = (intchar_t*)_elt;
	free(elt->s);
}

sem_t sem;


pthread_mutex_t    mutex2 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex_log = PTHREAD_MUTEX_INITIALIZER;

UT_ringbuffer *log_ringbuf;

//extern int layer2_len=14;
//extern u_char *buf_share = NULL;




buffer mysql_buffer, sqlserver_buffer, oracle_buffer, redis_buffer, oracle_buffer, postgres_buffer, sybase_buffer, shentong_buffer;
buffer syslog_buffer;

intchar_t ic;

UT_icd intchar_icd = {sizeof(intchar_t), NULL, intchar_copy, intchar_dtor};

//struct access_ctl_info access_info;

static void
sigint_h(int sig)	//ctrl+c is the signal to stop
{	(void)sig;	/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

int waf_htoi(char *s);


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


//int check_tcp_rebuild( int dir, int dbtype, int pkt_len_share, long tv_sec, int if_custom)//s_ip+8, s_port+4, flags+2, length+2


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

/*
int check_list(const u_char * buf, int bdir, int rs_len, long tv_sec)
{
	//printf("============================in check_list, result is 0=========================\n\n");
	if (buf[59]==0x61 && buf[60]==0x61)
	{
		return 1;
	}
	return 0;
}
*/


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
	u_int timestamp = 0;
//printf("getPacket0\n");
	if(buf_share[12]==0x08 && buf_share[13]==0x00 && buf_share[23]==0x06) //ipv4 and tcp
	{
		time_t t = time(NULL);
		timestamp = time(&t);
		//check_list(buf, dbdir, rs->len, timestamp); //dbdir is dbf version
		//check_list(buf, 1, pkt_len_share, timestamp);
		check_list_dba(buf, pkt_len_share, timestamp);
	}
	else if ( buf_share[12]==0x08 && buf_share[13]==0x00 )	//ip packet	for syslog.
	{	if ( buf_share[23]==0x11 && buf_share[36]==0x02 && buf_share[37]==0x02 )	//udp and 514
		{	//if ( check_list(buf) == 0 )
			//{
			//}
			//else
			//{
			//}
		}
	}
}


int read_pcap_name(FILE *pFile)
{	char mystring[54];
	count_read_file = 0;
	//delete_blank_line();
	while ( fgets (mystring , 54, pFile) != NULL)
	{	mystring[strlen(mystring)-1]='\0';
		if(check_if_file(mystring) > 0)
		{	strcpy(pcap_in_list[count_read_file], mystring);
			count_read_file++;
		}
	}
	if (count_read_file > 0)
	{
		count_for_main = 1;
	}
	return 1;
}

void* read_localpcap_process()
{	struct stat buf;
	int result;
	int config_time=0;
	while(1)
	{	FILE * pFile;
		pFile = fopen (pcap_config_file, "r");
		if (pFile == NULL)
		{	perror ("Error opening pcap_list file");
			sleep(1);
			//fclose (pFile);
			continue;
		}
		result =stat(pcap_config_file, &buf );
		if( result != 0 )
		{	perror( "error" );
			sleep(1);
			//fclose (pFile);
			continue;
		}
		if(config_time == 0)
		{	config_time = buf.st_mtime;
			read_pcap_name(pFile);
		}
		if(config_time == buf.st_mtime)
		{	//printf("nochange!!!\n");
		}
		else
		{	config_time = buf.st_mtime;
			read_pcap_name(pFile);
		}
		fclose(pFile);
		sleep(20);
	}
	return 0;
}

int delete_blank_line()
{	char delete_blank_line[100] = "sed -i '/^ *$/d' ";
	strcat(delete_blank_line, pcap_config_file);
	system(delete_blank_line);
	return 0;
}

int delete_list( char *pcap_name )	//delete the file list name
{	char delete_line_cmd[1000] = "sed -i \"s#";
	char delete_line_cmd2[] = "##g\" ";
	//char delete_blank_line[100] = "sed -i '/^ *$/d' ";

	strcat(delete_line_cmd, pcap_name);
	strcat(delete_line_cmd, delete_line_cmd2);
	strcat(delete_line_cmd, pcap_config_file);
	system(delete_line_cmd);
	return 0;
}

int delete_pcap_file( char *pcap_name )	//delete the pcap file
{	remove(pcap_name);
	return 0;
}


int read_local_main( char *pcap_name )
{	pcap_t *handle;
	char read_pcap_error[53];
	struct bpf_program filter;	//已经编译好的过滤器
	char pcap_name_tmp[53] = "\0";
	memcpy( pcap_name_tmp, pcap_name, strlen(pcap_name));
	FILE *pcap_loop_file;
	pcap_loop_file = fopen(pcap_name_tmp, "rb");
	if((handle = pcap_fopen_offline(pcap_loop_file, read_pcap_error))==NULL)  //打开文件
	{	printf("error:%s\n",read_pcap_error);
		delete_list(pcap_name_tmp);
		delete_pcap_file(pcap_name_tmp);
		//fclose(pcap_loop_file);
		pcap_close(handle);
		return 0;
	}
	pcap_compile(handle,&filter,"",1,0);		//函数返回-1为失败
	delete_list(pcap_name_tmp);
	if(pcap_setfilter(handle,&filter)==0)		//成功返回0.不成功返回-1
	{	pcap_loop(handle,-1,getPacket,1);	//捕获数据包
		//fclose(pcap_loop_file);
		pcap_close(handle);
	}
	else
		pcap_close(handle);

	printf("pcap_name_tmp is %s\n", pcap_name_tmp);
	
	//remove(pcap_name_tmp);
	delete_pcap_file(pcap_name_tmp);
	//printf("read_local_main5\n");
	usleep(100);
	//fclose(pcap_loop_file);
	return 1;
}


int main(int argc, char **argv)
{
	struct pollfd pollfd[2];
	//int ch;
	u_int burst = 1024, wait_link = 1;
	u_int bdir = 1;
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

	extern struct m_pool rebuild;
	m_init(&rebuild);



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

	pthread_t value_mask_process1;
	pthread_create(&value_mask_process1,NULL,value_mask_process,NULL);
	pthread_detach(value_mask_process1);

	pthread_t read_localpcap_process1;
	pthread_create(&read_localpcap_process1,NULL,read_localpcap_process,NULL);
	pthread_detach(read_localpcap_process1);

	sleep(1);
	while(1)
	{	if(count_for_main > 0)
		{	printf("count_read_file is %d\n", count_read_file);
			for (count_a = 0; count_a < count_read_file; count_a++)
			{	memset(file_name, "\0", 200);
				memcpy(file_name, pcap_in_list[count_a], 53 );
				//printf("222file_name is \n%s\n", file_name);
				printf("%s\n", file_name);
				count_sql = 0;
				read_local_main(file_name);
				printf("count_a is %d, file number is %d\n", count_a, count_a+1);
				usleep(100);
			}
			count_read_file = 0;
			delete_blank_line();
		}
		count_for_main = 0;
		sleep(5);
	}
	return 0;
}

