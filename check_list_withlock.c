#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include "define.h"
//#include "utlist_dbf.h"
#include "head.h"
#include "send_reset.h"

#if 0
static void HexToAscii(unsigned char *pHex,  char *pAscii, int nLen)
{
    unsigned char Nibble[2];
    unsigned int i,j;
    for (i = 0; i < nLen; i++){
        Nibble[0] = (pHex[i] & 0xF0) >> 4;
        Nibble[1] = pHex[i] & 0x0F;
        for (j = 0; j < 2; j++){
            if (Nibble[j] < 10){            
                Nibble[j] += 0x30;
            }
            else{
                if (Nibble[j] < 16)
                    Nibble[j] = Nibble[j] - 10 + 'a';
            }
            *pAscii++ = Nibble[j];
        }               // for (int j = ...)
    }           // for (int i = ...)
}
#endif

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
	int reset_flag = 1;
	int i, j;
	uint8_t total_len[2] = {0};
	buf_check_list = buf;                                                                              // buf_share
	pthread_mutex_lock(&mutex_config);
	DL_FOREACH(config_head,config_elt)
	{	if (config_elt->status == 1)	                                                            //该条生效启用
		{	if (config_elt->db_port[0] == buf_check_list[36] && config_elt->db_port[1] == buf_check_list[37])	//dir == 1
			{	if ( config_elt->dbip[0]==buf_check_list[30] && config_elt->dbip[1]==buf_check_list[31] && config_elt->dbip[2]==buf_check_list[32] && config_elt->dbip[3]==buf_check_list[33] )
				{	
					dba_config_struct * tmp = config_elt;
					if(!check_access_ip()) {                                                          //
					    printf("客户端ip在visit_rule范围里，调用check_tcp_rebuild\n");
						reset_flag = check_tcp_rebuild( bdir, tmp->db_type, pkt_len_share, timestamp, 0);
						//access_judge(access_info.sql, access_info.the_ip_port);
						//reset_flag = strategy_info.reset_flag;
						printf("dir 1 check_tcp_rebuild return %d\n", reset_flag);
						if(reset_flag == 0) {
							memcpy(total_len, buf_share+ 16, 2);
							printf("数据包原包发送\n");
							for (i = 0; i < (total_len[0] << 8) + total_len[1] + 14; i++) {
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
					config_elt = tmp;
					#if 0
					switch( config_elt->db_type )
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
					#endif 
				//	pthread_mutex_unlock(&mutex_config);
				//	printf("dir = 1,check_list2 result is %d\n", db_type_tmp * check_custom);
					//return (db_type_tmp * check_custom);
				}
			}
			else if ( config_elt->db_port[0] == buf_check_list[34] && config_elt->db_port[1] ==buf_check_list[35] )
			{	if ( config_elt->dbip[0]==buf_check_list[26] && config_elt->dbip[1]==buf_check_list[27] && config_elt->dbip[2]==buf_check_list[28] && config_elt->dbip[3]==buf_check_list[29] )
				{	
					reset_flag = check_tcp_rebuild( bdir, config_elt->db_type, pkt_len_share, timestamp, 0);
					/*
					uint8_t db_ip_port[6] = {0};
					char ip_port[13] = {0};
					memcpy(db_ip_port, buf_check_list + 26, 4);
					memcpy(db_ip_port + 4, buf_check_list + 34, 2);
					HexToAscii(db_ip_port, ip_port, 6);
					ip_port[12] = '\0';
					printf("判断掩码返回\n");
					reset_flag = check_value_mask(ip_port);
					*/
					printf("dir 2 check_tcp_rebuild return %d\n", reset_flag);
						if(reset_flag == 0) {
							memcpy(total_len, buf_share+ 16, 2);
							printf("数据包原包发送\n");
							for (i = 0; i < (total_len[0] << 8) + total_len[1] + 14; i++) {
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
					#if 0
					switch( config_elt->db_type )
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
					#endif
				//	pthread_mutex_unlock(&mutex_config);
				//	printf("dir = 2,check_list2 result is %d\n", db_type_tmp);
				//	return (db_type_tmp);
				}
			}
			else
			{	//printf("not in!\n");
				//printf("no match port\n");
			}
		}
	}
	if(strategy_info.reset_flag == 0 && reset_flag  == 1) {
		printf("没有匹配到数据库和客户端IP，发送原始数据包。\n");
		reset_flag = 0;
		//send_reset();
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