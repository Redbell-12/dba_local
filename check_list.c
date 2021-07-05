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

int check_list( const u_char * buf, int bdir, int pkt_len_share, long timestamp)
{
	int db_type_tmp = 0;
	int check_custom = 1;
	int reset_flag = -1;
	uint8_t total_len[2] = {0};
	buf_check_list = buf;                                                                              // buf_share
	pthread_mutex_lock(&mutex_config);
	DL_FOREACH(config_head,config_elt)
	{	if (config_elt->status == 1)	                                                            //该条生效启用
		{	if (config_elt->db_port[0] == buf_check_list[36] && config_elt->db_port[1] == buf_check_list[37])	//dir == 1
			{	if ( config_elt->dbip[0]==buf_check_list[30] && config_elt->dbip[1]==buf_check_list[31] && config_elt->dbip[2]==buf_check_list[32] && config_elt->dbip[3]==buf_check_list[33] )
				{	
					dba_config_struct * tmp = config_elt;
					if (visit_rule == 0) {
						printf("没有配置visit_rule规则，调用check_tcp_rebuild\n");
						reset_flag = check_tcp_rebuild( bdir, tmp->db_type, pkt_len_share, timestamp, 0);
						//access_judge(access_info.sql, access_info.the_ip_port);
						//reset_flag = strategy_info.reset_flag;
						printf("dir 1 check_tcp_rebuild return %d\n", reset_flag);
						if(reset_flag == 0) {
							memcpy(total_len, buf_share+ 16, 2);
							printf("数据包原包发送\n");
							for (int i = 0; i < (total_len[0] << 8) + total_len[1] + 14; i++) {
								if (i % 40 == 0)
									printf("\n\t");
								if (isprint(buf_share[i]))
									putchar(buf_share[i]);
								else
									putchar('.');
							}
							printf("\n");
						}
						goto JUMP;
					}
					int ret = check_access_ip();
					if (ret == 0) {                                                          //
					    visit_rule = 2;
						printf("客户端ip在visit_rule范围里，调用check_tcp_rebuild\n");
						reset_flag = check_tcp_rebuild( bdir, tmp->db_type, pkt_len_share, timestamp, 0);
						//access_judge(access_info.sql, access_info.the_ip_port);
						//reset_flag = strategy_info.reset_flag;
						printf("dir 1 check_tcp_rebuild return %d\n", reset_flag);
						if(reset_flag == 0) {
							memcpy(total_len, buf_share+ 16, 2);
							printf("数据包原包发送\n");
							for (int i = 0; i < (total_len[0] << 8) + total_len[1] + 14; i++) {
								if (i % 40 == 0)
									printf("\n\t");
								if (isprint(buf_share[i]))
									putchar(buf_share[i]);
								else
									putchar('.');
							}
							printf("\n");
						}
						goto JUMP;                                                              //已经完成包处理，所以，用goto跳过最后的reset组包。
					}
					
					else {
						visit_rule = 3;
						printf("客户端ip不在visit_rule范围里，调用check_tcp_rebuild函数\n");
						check_tcp_rebuild( bdir, tmp->db_type, pkt_len_share, timestamp, 0);
						//access_judge(access_info.sql, access_info.the_ip_port);
						//reset_flag = strategy_info.reset_flag;
						printf("dir 1 check_tcp_rebuild return %d\n", reset_flag);
						reset_flag = 1;
						goto JUMP;
					}
					config_elt = tmp;
				}
			}
			else if ( config_elt->db_port[0] == buf_check_list[34] && config_elt->db_port[1] ==buf_check_list[35] )
			{	if ( config_elt->dbip[0]==buf_check_list[26] && config_elt->dbip[1]==buf_check_list[27] && config_elt->dbip[2]==buf_check_list[28] && config_elt->dbip[3]==buf_check_list[29] )
				{	
					reset_flag = check_tcp_rebuild( bdir, config_elt->db_type, pkt_len_share, timestamp, 0);
					
					printf("dir 2 check_tcp_rebuild return %d\n", reset_flag);
						if(reset_flag == 0) {
							memcpy(total_len, buf_share+ 16, 2);
							printf("数据包原包发送\n");
							for (int i = 0; i < (total_len[0] << 8) + total_len[1] + 14; i++) {
								if (i % 40 == 0)
									printf("\n\t");
								if (isprint(buf_share[i]))
									putchar(buf_share[i]);
								else
									putchar('.');
							}
							printf("\n\n");
						}
						goto JUMP;                                                              //已经完成包处理，所以，用goto跳过最后的reset组包。
					
				}
			}
			else
			{	//printf("not in!\n");
				//printf("no match port\n");
			}
		}
	}
	if(reset_flag  == -1) {
		printf("没有匹配到数据库服务器IP，发送原始数据包。\n");
		reset_flag = 0;
		//send_reset();
	}
JUMP:
	pthread_mutex_unlock(&mutex_config);
	return reset_flag;
}

