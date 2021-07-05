#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include "define.h"
//#include "utlist_dbf.h"
#include "head.h"
#include "send_reset.h"

static int check_access_ip()
{
	uint32_t client_ip = 0; 
	int reset_flag = 1;
	DL_FOREACH(config_head, config_elt) {
		if(config_elt->db_ipp[0] == buf_check_list[30] && config_elt->db_ipp[1] == buf_check_list[31] && config_elt->db_ipp[2] == buf_check_list[32] && config_elt->db_ipp[3] == buf_check_list[33]
			&& config_elt->db_ipp[4] == buf_check_list[36] && config_elt->db_ipp[5] == buf_check_list[37]) {
			client_ip = (buf_check_list[26] << 24) + (buf_check_list[27] << 16) + (buf_check_list[28] << 8) + buf_check_list[29];
			if(client_ip >= config_elt->vis_ip1_int && client_ip <= config_elt->vis_ip2_int) {
				reset_flag = 0;
				break;
			}
		}
	}
	return reset_flag;
}

int check_list_dba( const u_char * buf, int pkt_len_share, long timestamp)
{
	int db_type_tmp = 0;
	int check_custom = 1;
	int reset_flag = 1;
	uint8_t total_len[2] = {0};
	buf_check_list = buf;                                                                              // buf_share
	pthread_mutex_lock(&mutex_config);
	DL_FOREACH(config_head,config_elt)
	{	if (config_elt->status == 1)	                                                            //该条生效启用
		{	if (config_elt->db_port[0] == buf_check_list[36] && config_elt->db_port[1] == buf_check_list[37]  &&	//dir == 1
			   config_elt->dbip[0]==buf_check_list[30] && config_elt->dbip[1]==buf_check_list[31] && config_elt->dbip[2]==buf_check_list[32] && config_elt->dbip[3]==buf_check_list[33] )
			{	
				dba_config_struct * tmp = config_elt;
				if (visit_rule == 0) {
					printf("没有配置visit_rule规则，调用check_tcp_rebuild\n");
					reset_flag = check_tcp_rebuild( 1, tmp->db_type, pkt_len_share, timestamp, config_elt->if_custom);	
					goto JUMP;
				}
				int ret = check_access_ip();
				if (ret == 0) {                                                          //
					    //visit_rule = 2;
					printf("客户端ip在visit_rule范围里，调用check_tcp_rebuild\n");
					reset_flag = check_tcp_rebuild( 1, tmp->db_type, pkt_len_share, timestamp, config_elt->if_custom);
					goto JUMP;                                                              //已经完成包处理，所以，用goto跳过最后的reset组包。
				}
				else {
					visit_rule = 3;
					printf("客户端ip不在visit_rule范围里，调用check_tcp_rebuild函数\n");
					//check_tcp_rebuild( 1, tmp->db_type, pkt_len_share, timestamp, 0);
					goto JUMP;
				}
				config_elt = tmp;
			}
			else if ( config_elt->db_port[0] == buf_check_list[34] && config_elt->db_port[1] ==buf_check_list[35] )
			{	
				if ( config_elt->dbip[0]==buf_check_list[26] && config_elt->dbip[1]==buf_check_list[27] && config_elt->dbip[2]==buf_check_list[28] && config_elt->dbip[3]==buf_check_list[29] )
				{	
					reset_flag = check_tcp_rebuild( 2, config_elt->db_type, pkt_len_share, timestamp, config_elt->if_custom);
					
					goto JUMP;                                                              //已经完成包处理，所以，用goto跳过最后的reset组包。
				}
			}
		}
	}
	
JUMP:
	pthread_mutex_unlock(&mutex_config);
	return reset_flag;
}

#if 0
...
...
...
if(bdir == 1)	//visitor to db
{
	time_t t = time(NULL);
	timestamp = time(&t);
	check_list_result = check_list2(buf);
	printf("in dbdir==1\n");
	if ( check_list_result == 0 )
	{	//return;	
	}
		
	else if ( check_list_result % 2 != 0 )
	{	count_sql++;	
	if ( check_list_result % 101 == 0 )
	{	if_custom = 1;
		check_custom = check_list_result/101;
	}
	else 
	{	if_custom = 0;	
		check_custom = check_list_result;
	}
	//printf("check_custom is %d\n",check_custom);		
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
	check_tcp_rebuild( bdir, dbtype, rs->len, timestamp, 0);
}
#endif 
