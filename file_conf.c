#include <stdio.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <pcre.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include "define.h"
#include "file_conf.h"
#include "send_reset.h"
//#include "utlist_dbf.h"

#define DBA_CONFIG_FILE       "/dev/shm/dba_config.txt"
#define POLICY_CONFIG_FILE    "/dev/shm/policy.json"
#define ACCESS_CONFIG_FILE    "/dev/shm/access_rule.txt"
#define MASK_CONFIG_FILE      "/dev/shm/value_mask.txt"

p_value_mask_t gp_mask_head = NULL;
p_value_mask_t gp_mask_elt = NULL;
p_value_mask_t gp_mask_tmp = NULL;
//================================================
#if 0
dba_config_struct *config_head = NULL; /* important- initialize to NULL! */
dba_config_struct *config_name, *config_elt, *config_tmp, config_etmp;
dba_policy_struct *policy_head = NULL; /* important- initialize to NULL! */
dba_policy_struct *policy_name, *policy_elt, *policy_tmp, policy_etmp, findstr_elt;
//policy_log_struct *policy_log_head = NULL; /* important- initialize to NULL! */
//policy_log_struct *policy_log_name, *policy_log_elt, *policy_log_tmp, policy_log_etmp;
access_rule_struct *access_head = NULL; /* important- initialize to NULL! */
access_rule_struct *access_name, *access_elt, *access_tmp, access_etmp;
#endif
pthread_mutex_t    mutex_config = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex_policy = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex_access = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex_mask = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t    mutex_printf = PTHREAD_MUTEX_INITIALIZER;   // 为了调式可以按顺序打印，所以用此变量，产品发布去掉此变量

int visit_rule;
//struct access_ctl_info access_info;

int dba_config_insert(FILE * pFile)
{	
	visit_rule = 0;
	pthread_mutex_lock(&mutex_config);
	DL_FOREACH_SAFE(config_head,config_elt,config_tmp) {
		DL_DELETE(config_head,config_elt);
		free(config_elt);
	}
	pthread_mutex_unlock(&mutex_config);
	char mystring[501];
	pthread_mutex_lock(&mutex_printf);
	printf("insert dba\n");
	while ( fgets (mystring , 500 , pFile) != NULL )
	{
		if(!memcmp(mystring,"[db_content]",10))
		{	while ( fgets (mystring , 300 , pFile) != NULL )
			{	if(memcmp(mystring,"[/db_content]",10))
				{	if ( (config_name = (dba_config_struct*)malloc(sizeof(dba_config_struct))) != NULL)
					{	const char *error;
    						int  erroffset;
						pthread_mutex_lock(&mutex_config);
						
						config_name->dbip[0]=(uint8_t)waf_htoi(mystring);
						config_name->dbip[1]=(uint8_t)waf_htoi(mystring+2);
						config_name->dbip[2]=(uint8_t)waf_htoi(mystring+4);
						config_name->dbip[3]=(uint8_t)waf_htoi(mystring+6);

						config_name->db_port[0]=(uint8_t)waf_htoi(mystring+8);
						config_name->db_port[1]=(uint8_t)waf_htoi(mystring+10);
						memcpy(config_name->key_ipp,mystring,12);

						config_name->status=atoi(mystring+13);
						config_name->db_type=atoi(mystring+16);
						config_name->if_custom=atoi(mystring+19);
						

						mystring[strlen(mystring)-1]=0x00;
						memcpy(config_name->custom_char, mystring + 22, 100);
						config_name->cus= pcre_compile(config_name->custom_char, 0, &error, &erroffset, NULL);

						memcpy(config_name->policy_open, mystring+19, 8);
						DL_APPEND(config_head, config_name);
						printf("dba_content : %s %02x %02x %s\n", config_name->key_ipp, config_name->status, config_name->db_type, config_name->policy_open);
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
						printf("dba_userkey : %s %d\n", config_name->userkey, config_name->status);
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
						visit_rule = 1;
						config_name->db_ipp[0]=(uint8_t)waf_htoi(mystring);
						config_name->db_ipp[1]=(uint8_t)waf_htoi(mystring+2);
						config_name->db_ipp[2]=(uint8_t)waf_htoi(mystring+4);
						config_name->db_ipp[3]=(uint8_t)waf_htoi(mystring+6);
						config_name->db_ipp[4]=(uint8_t)waf_htoi(mystring+8);
						config_name->db_ipp[5]=(uint8_t)waf_htoi(mystring+10);

						config_name->vis_ip1[0]=(uint8_t)waf_htoi(mystring+13);
						config_name->vis_ip1[1]=(uint8_t)waf_htoi(mystring+15);
						config_name->vis_ip1[2]=(uint8_t)waf_htoi(mystring+17);
						config_name->vis_ip1[3]=(uint8_t)waf_htoi(mystring+19);

						config_name->vis_ip2[0]=(uint8_t)waf_htoi(mystring+22);
						config_name->vis_ip2[1]=(uint8_t)waf_htoi(mystring+24);
						config_name->vis_ip2[2]=(uint8_t)waf_htoi(mystring+26);
						config_name->vis_ip2[3]=(uint8_t)waf_htoi(mystring+28);

						config_name->vis_ip1_int = (config_name->vis_ip1[0] << 24) + (config_name->vis_ip1[1] << 16) + (config_name->vis_ip1[2] << 8) + config_name->vis_ip1[3]; 
						config_name->vis_ip2_int = (config_name->vis_ip2[0] << 24) + (config_name->vis_ip2[1] << 16) + (config_name->vis_ip2[2] << 8) + config_name->vis_ip2[3];
						DL_APPEND(config_head, config_name);
 
						printf("dba_visit : %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n", 
						config_name->db_ipp[0], config_name->db_ipp[1], config_name->db_ipp[2], 
						config_name->db_ipp[3], config_name->db_ipp[4], config_name->db_ipp[5],
						config_name->vis_ip1[0], config_name->vis_ip1[1], config_name->vis_ip1[2], config_name->vis_ip1[3],
						config_name->vis_ip2[0], config_name->vis_ip2[1], config_name->vis_ip2[2], config_name->vis_ip2[3]);
						pthread_mutex_unlock(&mutex_config);
					}
				}
				else
				{	break;
				}
			}
		}
	}
	pthread_mutex_unlock(&mutex_printf);
	return 1;
}


int dba_policy_insert(FILE * pFile)
{	
	char buff[10] = {0};
	
	pthread_mutex_lock(&mutex_policy);
	DL_FOREACH_SAFE(policy_head,policy_elt,policy_tmp) {
		DL_DELETE(policy_head,policy_elt);
		free(policy_elt);
	}
	char mystring[2000];
	pthread_mutex_lock(&mutex_printf);
	printf("insert policy!\n");
	while ( fgets (mystring , 2000 , pFile) != NULL ){
		if(!memcmp(mystring,"[dba_rule_zcp]",13)){
			if ( (policy_name = (dba_policy_struct*)malloc(sizeof(dba_policy_struct))) != NULL){
				if(fgets (mystring , 2000 , pFile) != NULL)
				{	
					memcpy(policy_name->uuid,mystring+24,36);
					policy_name->uuid[36] = '\0';
					memcpy(policy_name->key_name,mystring,10);
					memcpy(policy_name->key_ipp,mystring+11,12);
					memcpy(buff,mystring + 61, 2);
					policy_name->log_type=atoi(buff);
					memcpy(buff,mystring + 64, 2);
					policy_name->action=atoi(buff);
					memcpy(buff,mystring + 67, 2);
					policy_name->str_len=atoi(buff);
					memcpy(buff, mystring + 70, 2);
					policy_name->reset_flag = atoi(buff);
					
					printf("policy userkey : %s\n", policy_name->key_name);
					printf("policy ip_port : %s\n", policy_name->key_ipp);
					printf("policy uuid : %s\n", policy_name->uuid);
					printf("policy log_type : %d\n", policy_name->log_type);
					printf("policy action : %d\n", policy_name->action);
					printf("policy str_len : %d\n", policy_name->str_len);
					printf("policy reset_flag : %d\n", policy_name->reset_flag);
				}
				const char *error;
    			int  erroffset;
				if(fgets (mystring , 2000 , pFile) != NULL)
				{	mystring[strlen(mystring)-1]=0x00;
					memcpy(policy_name->re_char,mystring,2000);
					printf("policy regex : %s\n", policy_name->re_char);
					
					policy_name->re= pcre_compile(policy_name->re_char, 0, &error, &erroffset, NULL);
				}
				if(fgets (mystring , 2000 , pFile) != NULL)
				{	mystring[strlen(mystring)-1]=0x00;
					memcpy(policy_name->replace,mystring,2000);
					//printf("policy replace : %s\n", policy_name->replace);
				}
				DL_APPEND(policy_head, policy_name);		
			}
		}
	}
	pthread_mutex_unlock(&mutex_printf);
	pthread_mutex_unlock(&mutex_policy);	
	return 1;
}


int access_rule_insert( FILE * pFile )
{	pthread_mutex_lock(&mutex_access);
	DL_FOREACH_SAFE( access_head, access_elt, access_tmp )
	{	DL_DELETE( access_head, access_elt );
		free( access_elt );
	}
	pthread_mutex_unlock(&mutex_access);

	pthread_mutex_lock(&mutex_printf);
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
							memcpy(access_name->operate_type, mystring+19, 40);
							access_name->operate_type[strlen(access_name->operate_type) - 1] = '\0';
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
							if (line1_copy == 0)
							{
								access_name->line2=atoi(mystring+21);
							}
							else
							{
								while(line1_copy)
								{
									line_n++;
									line1_copy /= 10;
								}
								printf("line_n is %d\n",line_n);
								access_name->line2=atoi(mystring+19+1+line_n);
								printf("line2 is %d\n", access_name->line2);
							}
							
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
	pthread_mutex_unlock(&mutex_printf);
	return 1;
}

void* dba_config_process()	//read config file
{	char config_file[50]= DBA_CONFIG_FILE;
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


void* dba_policy_process()	//read policy file
{	char policy_file[50] = POLICY_CONFIG_FILE;
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


void* access_rule_process()	//read access file
{	char access_file[50] = ACCESS_CONFIG_FILE;
	int access_time=0;
	while(1)
	{	FILE * pFile;
		pFile = fopen (access_file, "r");
		if (pFile == NULL){	perror ("Error opening file");	}
		struct stat buf;
		int result;
		result =stat(access_file, &buf );
		if( result != 0 ){	perror( "error" );	sleep(1);	continue;	}		
		if(access_time==0)
		{	access_time=buf.st_mtime;
			access_rule_insert(pFile);
		}
		if(access_time==buf.st_mtime)
		{	//printf("nochange!!!\n");
		}
		else
		{	printf("config change!!!!!\n");
			access_time=buf.st_mtime;
			access_rule_insert(pFile);
		}
		fclose (pFile);
		sleep(1);
	}
	return 0;
}

int value_mask_insert(FILE * pFile)
{
	char mystring[2000] = { 0 };
	char buff[10] = { 10 };
	
	p_value_mask_t p_mask_content = NULL;

	pthread_mutex_lock(&mutex_mask);
	DL_FOREACH_SAFE(gp_mask_head, gp_mask_elt, gp_mask_tmp) {
		DL_DELETE(gp_mask_head, gp_mask_elt);
		free(gp_mask_elt);
	}
	pthread_mutex_lock(&mutex_printf);
	printf("insert mask!\n");
	while (fgets(mystring, 2000, pFile) != NULL) {
		if (!memcmp(mystring, "[dba_rule_zcp]", 13)) {
			if ((p_mask_content = (p_value_mask_t)malloc(sizeof(value_mask_t))) != NULL) {
				if (fgets(mystring, 2000, pFile) != NULL) {
					memcpy(p_mask_content->uuid, mystring + 24, 36);
					p_mask_content->uuid[36] = '\0';
					memcpy(p_mask_content->userkey, mystring, 10);
					memcpy(p_mask_content->ip_port, mystring + 11, 12);
					memcpy(buff, mystring + 61, 2);
					p_mask_content->db_type = atoi(buff);
					memcpy(buff, mystring + 64, 2);
					p_mask_content->flag = atoi(buff);
					memcpy(buff, mystring + 67, 2);
					p_mask_content->str_len = atoi(buff);
					
					printf("mask userkey : %s\n", p_mask_content->userkey);
					printf("mask ip_port : %s\n", p_mask_content->ip_port);
					printf("mask uuid : %s\n", p_mask_content->uuid);
					printf("mask db_type : %d\n", p_mask_content->db_type);
					printf("mask flag : %d\n", p_mask_content->flag);
					printf("mask str_len : %d\n", p_mask_content->str_len);
				}
				const char *error;
				int  erroffset;
				if (fgets(mystring, 2000, pFile) != NULL) {
					mystring[strlen(mystring) - 1] = 0x00;
					memcpy(p_mask_content->value, mystring, 2000);
					printf("mask value : %s\n", p_mask_content->value);
				}
				if (fgets(mystring, 2000, pFile) != NULL) {
					mystring[strlen(mystring) - 1] = 0x00;
					memcpy(p_mask_content->mask, mystring, 2000);
					printf("mask mask : %s\n", p_mask_content->mask);
				}
				DL_APPEND(gp_mask_head, p_mask_content);
			}
		}
	}
	pthread_mutex_unlock(&mutex_printf);
	pthread_mutex_unlock(&mutex_mask);
	return 0;
}

void *value_mask_process(void *arg)
{
	char mask_file[50] = MASK_CONFIG_FILE;
	int mask_time = 0;
	while (1) {
		FILE *pFile;
		pFile = fopen(mask_file, "r");
		if (pFile == NULL) {
			perror("Error opening file");
			break;
		}
		struct stat buf;
		int result;
		result = stat(mask_file, &buf);
		if (result != 0) {
			perror("error");
			sleep(1);
			continue;
		}
		if (mask_time == 0) {
			mask_time = buf.st_mtime;
			value_mask_insert(pFile);
		}
		if (mask_time == buf.st_mtime) {	//printf("nochange!!!\n");
		}
		else {
			printf("config change!!!!!\n");
			mask_time = buf.st_mtime;
			value_mask_insert(pFile);
		}
		fclose(pFile);
		sleep(1);
	}

	return 0;
}

