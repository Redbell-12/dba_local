#include <stdio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcre.h>
#include <string.h>
#include "define.h"
#include "access_judge.h"
#include "file_conf.h"
//#include "utlist_dbf.h"
#include "head.h"
#include "send_reset.h"

#define  CORRECT               "00000000-0000-0000-0000-000000000000"
#define  BADDEN_USER      "00000000-0000-0000-0000-000000000001"
#define  BADDEN_DBNAME  "00000000-0000-0000-0000-000000000002"
#define  BADDEN_TBNAME   "00000000-0000-0000-0000-000000000003"
#define  BADDEN_CLIENTIP "00000000-0000-0000-0000-000000000004"
#define  BADDEN_APPTYPE  "00000000-0000-0000-0000-000000000005"
#define  BADDEN_OPSTYPE  "00000000-0000-0000-0000-000000000006"
#define  BADDEN_WHERE     "00000000-0000-0000-0000-000000000007"
#define  BADDEN_LINENUM  "00000000-0000-0000-0000-000000000008"

strategy_info_t  strategy_info = {
	.uuid = CORRECT,
	.reset_flag = 0,
};
//char strategy_number[37] = "00000000-0000-0000-0000-000000000000";
#if 0
int check_value_mask(char *the_ip_port)
{
	int reset_flag = 0;
	int retval = 0;
	DL_FOREACH(gp_mask_head, gp_mask_elt)
	{
		if(!memcmp(gp_mask_elt->ip_port, the_ip_port, 12)) {
			if(gp_mask_elt->flag) {
				retval = replace_reponse_data(gp_mask_elt->value, gp_mask_elt->mask, gp_mask_elt->str_len);
				if(retval == 2 && reset_flag == 0)
					reset_flag = 2;
			}
		}
	}
	return reset_flag;
}
#endif

int check_value_mask(char *the_ip_port)
{
	int reset_flag = 0;
	replace_info value_mask_info;

	memset(&value_mask_info, 0, sizeof(replace_info));

	DL_FOREACH(gp_mask_head, gp_mask_elt)
	{
		if(!memcmp(gp_mask_elt->ip_port, the_ip_port, 12)) {
			if(gp_mask_elt->flag) {
				find_value(gp_mask_elt->value, gp_mask_elt->str_len, gp_mask_elt->mask, &value_mask_info);
			}
		}
	}
	if(value_mask_info.value_pos[0] > 0) {
		replace_reponse_data(&value_mask_info);
		reset_flag = 2;
	}

	return reset_flag;
}

int check_policy_dba( char *src, char* the_ip_port)
{	
	printf("debuf1022-check_policy_dba\n");
	int  ovector[OVECCOUNT] = {0};
	int  rc, i;
	int log_len=strlen(src);
	char policy_data[1024] = {0};
//	pthread_mutex_lock(&mutex_policy);
	DL_FOREACH(policy_head,policy_elt)
	{	if(!memcmp(policy_elt->key_ipp, the_ip_port, 12) || !memcmp(policy_elt->key_ipp,key_ipp_zero,12))
		{	if ( ( rc = pcre_exec(policy_elt->re, NULL, src, strlen(src), 0, 0, ovector, OVECCOUNT)) != PCRE_ERROR_NOMATCH )
			{	
				if (policy_elt->action == 1)                                                  //策略开启
				{	//pthread_mutex_unlock(&mutex_policy);
					if(policy_elt->reset_flag == 2) {
						printf("call replace_request_data\n");
						memcpy(policy_data, src+ovector[0], ovector[1] - ovector[0]);
						replace_request_data(policy_data, ovector[1] - ovector[0]);
						strategy_info.reset_flag = 2;
					}
					else if(policy_elt->reset_flag == 1) {
						//printf("call send_reset\n");
						//send_reset();
						strategy_info.reset_flag = 1;
					}
					memcpy(strategy_info.uuid, policy_elt->uuid, 36);
					strategy_info.uuid[36] = '\0';
					printf("policy uuid is %s reset_flag %d\n", policy_elt->uuid, strategy_info.reset_flag);
					break;
				}
				else if (policy_elt->action == 0)                                     //策略关闭
				{	//pthread_mutex_unlock(&mutex_policy);
					strategy_info.reset_flag = 0;
					break;
					//return strategy_info.reset_flag ;
				}
			}
			else 
			{	printf("no match\n");
			}
		};
	}
//	pthread_mutex_unlock(&mutex_policy);
	return strategy_info.reset_flag;
}

//====================================access_rule begin=================================================
int access_check_user_name(char* the_ip_port, char *user_name)
{	int  return_code = 0;
	int user_name_len = strlen(user_name);
	printf("user_name in access is %s, %d\n", user_name, user_name_len);
	DL_FOREACH(access_head,access_elt)
	{	if(!memcmp(access_elt->db_ipport, the_ip_port, 12) || !memcmp(access_elt->db_ipport,key_ipp_zero,12))
		{	if (access_elt->acc_type == 1)
			{	
				printf("ip %s, acc_type:%d\n", access_elt->db_ipport, access_elt->acc_type);
				if ( ((int)strlen(access_elt->user_name) - 1 == user_name_len)  && !memcmp(access_elt->user_name, user_name, user_name_len ) )
				//if ( (strlen(access_elt->user_name) - 1 == strlen(user_name))  && ( rc = pcre_exec(access_elt->user_name_pcre, NULL, user_name, strlen(user_name), 0, 0, ovector, OVECCOUNT)) != PCRE_ERROR_NOMATCH )
				{	printf("policy access system_find_OK!!!!,user_name:%s\n",access_elt->user_name);
					return_code = 1;
					return return_code;
				}
				else
				{	//printf("no match\n");
					return_code = 0;
				}
			}
		}
	}
	return return_code;
}

int access_check_db_name(char* the_ip_port, char *db_name)
{	int  return_code = 0;
	int db_name_len = strlen(db_name);
	DL_FOREACH(access_head,access_elt)
	{	if(!memcmp(access_elt->db_ipport, the_ip_port, 12) || !memcmp(access_elt->db_ipport,key_ipp_zero,12))
		{	if (access_elt->acc_type == 2)
			{	if ( ((int)strlen(access_elt->db_name) - 1 == db_name_len)  && !memcmp(access_elt->db_name, db_name, db_name_len ) )
				{	printf("policy access system_find_OK!!!!,db_name:%s\n",access_elt->db_name);
					return_code = 1;
					return return_code;
				}
				else
				{	//printf("no match\n");
					return_code = 0;
				}
			}
		}
	}
	return return_code;
}

int access_check_table_name(char* the_ip_port, char *tbname_array)
{	int return_code = 0;
	//int db_name_len = strlen(db_name);
	printf("tbname_array is %s\n", tbname_array);
	printf("strlen(tbname_array) is %d\n", strlen(tbname_array));
	DL_FOREACH(access_head,access_elt)
	{	if(!memcmp(access_elt->db_ipport, the_ip_port, 12) || !memcmp(access_elt->db_ipport,key_ipp_zero,12))
		{	if (access_elt->acc_type == 3)
			{	printf("strlen(access_elt->table_name) is %d\n", strlen(access_elt->table_name));
				if ( (strlen(access_elt->table_name) - 1 == strlen(tbname_array))  && (memcmp(access_elt->table_name, tbname_array, strlen(tbname_array) ) == 0) )
				{	printf("==access table name find_OK!!!!,table_name:%s\n",access_elt->table_name);
					return_code = 1;
					return return_code;
				}
				else
				{	printf("%s: no match\n", access_elt->table_name);
					return_code = 0;
				}
			}
		}
	}
	return return_code;
}

int access_check_client_type(char* the_ip_port, int client_type)
{	int return_code = 0;
	//printf("==========client_type is %d\n",client_type);
	DL_FOREACH(access_head,access_elt)
	{	if(!memcmp(access_elt->db_ipport, the_ip_port, 12) || !memcmp(access_elt->db_ipport,key_ipp_zero,12))
		{	if (access_elt->acc_type == 5)
			{	//printf("================access_elt->client_type is %d\n", access_elt->client_type);
				if ( access_elt->client_type == client_type )
				{	printf("access client_type find_OK!!!!,client_type:%d\n",access_elt->client_type);
					return_code = 1;
					return return_code;
				}
				else
				{	//printf("no match\n");
					return_code = 0;
				}
			}
		}
	}
	return return_code;
}

int access_check_operate_type(char* the_ip_port, int operate_type)
{	int return_code = 0;
	DL_FOREACH(access_head,access_elt)
	{	if(!memcmp(access_elt->db_ipport, the_ip_port, 12) || !memcmp(access_elt->db_ipport,key_ipp_zero,12))
		{	if (access_elt->acc_type == 6)
			{	printf("access_elt->operate_type[operate_type] is %d:%c\n", operate_type, access_elt->operate_type[operate_type]);
				if ( access_elt->operate_type[operate_type] == '1' )
				{	printf("policy access system_find_OK!!!!,operate_type:%s\n",access_elt->operate_type);
					return_code = 1;
					return return_code;
				}
				else
				{	//printf("no match\n");
					return_code = 0;
				}
			}
		}
	}
	return return_code;
}

int access_check_where(char* the_ip_port, int where)
{	int return_code = 0;
	DL_FOREACH(access_head,access_elt)
	{	if(!memcmp(access_elt->db_ipport, the_ip_port, 12) || !memcmp(access_elt->db_ipport,key_ipp_zero,12))
		{	if (access_elt->acc_type == 7)
			{	if ( access_elt->where == where )
				{	printf("policy access system_find_OK!!!!,where:%d\n",access_elt->where);
					return_code = 1;
					return return_code;
				}
				else
				{	//printf("no match\n");
					return_code = 0;
				}
			}
		}
	}
	return return_code;
}

int access_check_line(char* the_ip_port, int line1, int line2)
{	int return_code = 1;
	DL_FOREACH(access_head,access_elt)
	{	if(!memcmp(access_elt->db_ipport, the_ip_port, 12) || !memcmp(access_elt->db_ipport,key_ipp_zero,12))
		{	if (access_elt->acc_type == 8)
			{	if ( line1 >= access_elt->line1 && line2 <= access_elt->line2 )
				{	printf("policy access system_find_OK!!!!,line1:%d line2:%d\n",access_elt->line1, access_elt->line2);
					return_code = 1;
					return return_code;
				}
				else
				{	//printf("no match\n");
					return_code = 0;
				}
			}
		}
	}
	return return_code;
}

int access_judge( char *src, char* the_ip_port, struct access_ctl_info access_info)
{	
	//return 0;
	printf("==begin acccess_judge==\n");
	printf("access_info.username is %s\n", access_info.username);
	printf("access_info.tbname_array[0] is %s\n",access_info.tbname_array[0]);
	printf("access_info.dbname is %s\n", access_info.dbname);
	printf("access_info.operation_type is %d\n", access_info.operation_type);
	strategy_info.reset_flag = 0;
	memset(strategy_info.uuid, 0, 37);
	strcpy(strategy_info.uuid, CORRECT);

	int check_user_name_result = 1;
	int check_db_name_result = 1;
	int check_table_name_result[10] = {0};
	int check_table_name_result_all = 1;
	int check_table_count = 1;
	int check_client_type_result = 1;
	int check_operate_type_result = 1;
	int check_where_result = 1;
	int check_line_result = 1;
//	int check_policy_dba_result = 0;
	//int access_judge_result = 1;

	int check_user_name_need = 1;
	int check_db_name_need = 1;
	int check_table_name_need = 1;
	int check_client_type_need = 1;
	int check_operate_type_need = 1;
	int check_where_need = 1;
	int check_line_need = 1;

	if(visit_rule == 3) {
		strategy_info.reset_flag = 1;
		strcpy(strategy_info.uuid, BADDEN_CLIENTIP);
		printf("check_client_ip_result is 0 uuid: %s\n", strategy_info.uuid);
		goto JUMP;
	}
	//printf("username is %s\n", access_info.username);

	DL_FOREACH(access_head,access_elt)
	{	
		if(!memcmp(access_elt->db_ipport, the_ip_port, 12) || !memcmp(access_elt->db_ipport,key_ipp_zero,12))
		{	
			printf("ip in it\n");
			printf("access_elt->acc_type is %d\n", access_elt->acc_type);
			//printf("access_info.username is %s\n", access_info.username);
			//printf("~~~len of access_info.username is %d\n", strlen(access_info.username));
			//printf("access_info.dbname is %s\n", access_info.dbname);
			//printf("access_info.operation_type is %d\n", access_info.operation_type);
			if (access_elt->acc_type == 1 &&  memcmp(access_info.username,"0",1)!=0 && strlen(access_info.username)!=0  )
			{	check_user_name_need = 0;
				//printf("**check_user_name_result is %d\n", check_user_name_result);
			}
			if (access_elt->acc_type == 2 && memcmp(access_info.dbname,"0", 1) !=0 && strlen(access_info.dbname)!=0 )
				check_db_name_need = 0;
			if (access_elt->acc_type == 3 && access_info.tbname_array[0] != 0)
				check_table_name_need = 0;
			if (access_elt->acc_type == 5 && access_info.client_type > 0 && access_info.client_type < 100)
				check_client_type_need = 0;
			if (access_elt->acc_type == 6 && access_info.operation_type > 0 && access_info.operation_type < 100)
				check_operate_type_need = 0;
			if (access_elt->acc_type == 7 && access_info.if_where == 1)
				check_where_need = 0;
			if (access_elt->acc_type == 8 && access_info.line_limit[0] != -1 && access_info.line_limit[1] != -1)
				check_line_need = 0;
		}
	}
	printf("01:%d, 02:%d, 03:%d, 05:%d, 06:%d, 07:%d, 08:%d\n ", check_user_name_need, check_db_name_need, check_table_name_need, check_client_type_need, check_operate_type_need, check_where_need, check_line_need);
	if(check_user_name_need == 0)
		check_user_name_result = access_check_user_name( the_ip_port, access_info.username );
	if(check_db_name_need == 0)
		check_db_name_result = access_check_db_name( the_ip_port, access_info.dbname );
	if(check_table_name_need == 0)
	{	//check_table_name_result_all = 1;
		for(check_table_count = 0; check_table_count < 10; check_table_count++)
		{	
			if(access_info.tbname_array[check_table_count] != 0)
			{	
				printf("strlen(access_info.tbname_array[check_table_count]) is %d\n", strlen(access_info.tbname_array[check_table_count]));
				check_table_name_result[check_table_count] = access_check_table_name( the_ip_port, access_info.tbname_array[check_table_count] );
				printf("+++check_table_name_result[check_table_count] is %d\n", check_table_name_result[check_table_count]);
				check_table_name_result_all = check_table_name_result_all * check_table_name_result[check_table_count];
				printf("---check_table_name_result_all is %d\n", check_table_name_result_all);
				if(check_table_name_result_all == 0)
				{	break;
//MAYBE BAD!!! DEBUG FOR A MISTAKE OF ; AFTER IF()
				}
			}
			else
			{	break;
			}
		}
		//printf("A0003333\n");
	}
	if(check_client_type_need == 0)
		check_client_type_result = access_check_client_type( the_ip_port, access_info.client_type );
	if(check_operate_type_need == 0)
		check_operate_type_result = access_check_operate_type( the_ip_port, access_info.operation_type -1 );
	if(check_where_need == 0)
		check_where_result = access_check_where( the_ip_port, access_info.if_where );
	if(check_line_need == 0)
		check_line_result = access_check_line( the_ip_port, access_info.line_limit[0], access_info.line_limit[1] );

//	printf("11check_user_name_result is %d\n", check_user_name_result);
//	printf("12check_db_name_result is %d\n", check_db_name_result);
//	printf("13check_table_name_result_all is %d\n", check_table_name_result_all);
//	printf("15check_client_type_result is %d\n", check_client_type_result);
//	printf("16check_operate_type_result is %d\n", check_operate_type_result);
//	printf("17check_where_result is %d\n", check_where_result);
//	printf("18check line result is %d\n", check_line_result);

//access_judge_result is 1 means through, 0 means cut.
	Globalaccess_judge_result = check_user_name_result * check_db_name_result * check_table_name_result_all * check_client_type_result * check_operate_type_result * check_where_result * check_line_result;
	printf("===========Globalaccess_judge_result is %d\n", Globalaccess_judge_result);

	if(Globalaccess_judge_result > 0)
	{	
		printf("debuf1022\n");
		check_policy_dba_result = check_policy_dba( src, the_ip_port );
		printf("check_policy_dba_result is %d\n", check_policy_dba_result);
		return check_policy_dba_result;
	}
	else
	{
		//printf("call send_reset\n");
		//send_reset();
		strategy_info.reset_flag = 1;
		//为了保持与永杰调用access_judge函数兼容，保留int返回值，用全局变量返回结构体strategy_info
		if(check_user_name_result == 0)
		{	
			strcpy(strategy_info.uuid, BADDEN_USER);
			printf("check_user_name_result is %d uuid: %s\n", check_user_name_result, strategy_info.uuid);
			goto JUMP;
			//return 11;
		}
		if(check_db_name_result == 0)
		{	
			strcpy(strategy_info.uuid, BADDEN_DBNAME);
			printf("check_db_name_result is %d uuid: %s\n", check_db_name_result, strategy_info.uuid);
			goto JUMP;
			//return 12;
		}
		if(check_table_name_result_all == 0)
		{	
			strcpy(strategy_info.uuid, BADDEN_TBNAME);
			printf("check_table_name_result_all is %d uuid: %s\n", check_table_name_result_all, strategy_info.uuid);
			goto JUMP;
			//return 13;
		}
		if(check_client_type_result == 0)
		{	
			strcpy(strategy_info.uuid, BADDEN_APPTYPE);
			printf("check_client_type_result is %d uuid: %s\n", check_client_type_result, strategy_info.uuid);
			goto JUMP;
			//return 15;
		}
		if(check_operate_type_result == 0)
		{	
			strcpy(strategy_info.uuid, BADDEN_OPSTYPE);
			printf("check_operate_type_result is %d uuid: %s\n", check_operate_type_result, strategy_info.uuid);
			goto JUMP;
			//return 16;
		}
		if(check_where_result == 0)
		{	
			strcpy(strategy_info.uuid, BADDEN_WHERE);
			printf("check_where_result is %d uuid: %s\n", check_where_result, strategy_info.uuid);
			goto JUMP;
			//return 17;
		}
		if(check_line_result == 0)
		{	
			strcpy(strategy_info.uuid, BADDEN_LINENUM);
			printf("check line result is %d uuid: %s\n", check_line_result, strategy_info.uuid);
			goto JUMP;
			//return 18;
		}
	}	

JUMP:
	return 0;
}
//====================================access_rule done=================================================
