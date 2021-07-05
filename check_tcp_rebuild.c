#include <stdio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "head.h"
#include "access_judge.h"
#include "check_tcp_rebuild.h"
#include "define.h"

int if_payload_complete(unsigned char *buf_share,int pkt_len_share,int dir,int db_type);
struct m_pool rebuild; 

int check_tcp_rebuild( int dir, int dbtype, int pkt_len_share, long tv_sec, int if_custom)//s_ip+8, s_port+4, flags+2, length+2
{
	printf("in check_tcp_rebuild\n");
	int ret=0; //应用层的返回值
	char my_ip_port_char[36] = "";
	char str_tmp[5] = "";
	char *rebuild_all_tcp;
//	int tcp_rebuild = 0;	//0 means no rebuild, 1 means need rebuild, 2 means can be rebuild and restore.
	int packet_length = 0;
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
		return 0;
	ifack= (buf_share[layer1_len+33] >> (9-4 - 1)) & 1;
	ifpsh= (buf_share[layer1_len+33] >> (9-5 - 1)) & 1;
	ifsyn= (buf_share[layer1_len+33] >> (9-7 - 1)) & 1;
	iffin= (buf_share[layer1_len+33] >> (9-8 - 1)) & 1;

	seq_num = (unsigned int *)(buf_share+layer1_len+24);	//modi define 20200529
	ack_num = (unsigned int *)(buf_share+layer1_len+28);	//modi define 20200529
	if (ifack == 1 && ifsyn == 0 && dir == 2)	//from db to visitor
	{
		printf("check_tcp_rebuild, dir = 2\n");
		memcpy(db_mac, buf_share+6, 6);
		memcpy(visit_mac, buf_share, 6);

		if ( *(buf_share + 5) == 0x00 && (dbtype == 1||dbtype == 4) ){
			return 0;
		}
		HASH_FIND_STR(my_tcptable, my_ip_port_char, str_find1);

		if(!str_find1)	//not find
		{
			str_add = (struct my_tcptable_struct*)m_malloc(&rebuild,sizeof(struct my_tcptable_struct));
			if(str_add==NULL)
				return 0;

			memset(str_add->TCP_BIG_DATA, 0x00, TCP_WINDOW);
			memcpy(str_add->hexname, my_ip_port_char, 36);

			pthread_mutex_lock(&mutex);
			str_add->seq_num = htonl(*seq_num);
			str_add->ack_num = htonl(*ack_num);
			str_add->first_seq = str_add->seq_num;
			str_add->tcp_data_len = str_add->seq_num - str_add->first_seq + data_length;
			pthread_mutex_unlock(&mutex);

			if (data_length == 0)	{
				return 0;
			}
			memcpy(str_add->TCP_BIG_DATA, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);
			//copy data part to TCP_BIG_DATA

			HASH_ADD_STR( my_tcptable, hexname, str_add );
			if(if_payload_complete(buf_share, pkt_len_share, dir, dbtype)) 	//mysql use 0xfe for end
			{	//dbtype = 1;//this is a min version, both 1 and 4 use mysql protocol
				if (data_length < 4)	{
					HASH_DEL( my_tcptable, str_add );
					m_free(str_add);
					return 0;
				}
				else
				{	ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
					HASH_DEL( my_tcptable, str_add );
					m_free(str_add);
					return ret;
				}
			}
			else if(if_payload_complete(buf_share, pkt_len_share, dir, dbtype))//sqlserver oracle postgre shentong
			{	if (data_length < 8)
				{	HASH_DEL( my_tcptable, str_add );
					m_free(str_add);
					return 0;
				}
				else
				{	ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
					HASH_DEL( my_tcptable, str_add );
					m_free(str_add);
					return ret;
				}
			}
		}
		else if (str_find1)	//find it!
		{
			before_ack = str_find1->ack_num;
			before_length = str_find1->tcp_data_len;
			first_inside_seq = str_find1->first_seq;

			if (data_length == 0)
			{	HASH_DEL( my_tcptable, str_find1 );
				m_free(str_find1);
				return 0;
			}
			if (htonl(*ack_num) == before_ack)
			{	offset = htonl(*seq_num) - first_inside_seq;
				if(offset <= 0)
					offset = abs(offset);
				before_length = offset + data_length;
				if (before_length > TCP_WINDOW)
				{
					HASH_DEL( my_tcptable, str_find1 );	
					m_free(str_find1);
					return 0;
				}
				memcpy(str_find1->TCP_BIG_DATA + offset, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);

				str_find1->seq_num = htonl(*seq_num);
				if ( *(buf_share + pkt_len_share - 5)==0xfe && (dbtype == 1||dbtype == 4) )
				{	//dbtype = 1;	//this is a min version, both 1 and 4 use mysql protocol
					if (before_length < 4)
					{	HASH_DEL( my_tcptable, str_find1 );
						m_free(str_find1);
						return 0;
					}
					else
					{	ret=proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, before_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_find1 );
						m_free(str_find1);
						return ret;
					}
				}
				else if ( *(buf_share + pkt_len_share - 13)==0xfe && dbtype == 2 )
				{	if (before_length < 8)
					{	HASH_DEL( my_tcptable, str_find1 );
						m_free(str_find1);
						return 0;
					}
					else
					{	ret=proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, before_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_find1 );
						m_free(str_find1);
						return ret;
					}
				}
				else if ( dbtype == 3 )
				{	if (before_length < 8)
					{	HASH_DEL( my_tcptable, str_find1 );
						m_free(str_find1);
						return 0;
					}
					else
					{	ret=proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, before_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_find1 );
						m_free(str_find1);
						return ret;
					}
				}
				else if ( *(buf_share + pkt_len_share - 1)==0x00 && dbtype == 9 )
				{	if (before_length < 8)
					{	HASH_DEL( my_tcptable, str_find1 );
						m_free(str_find1);
						return 0;
					}
					else
					{	ret=proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, before_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_find1 );
						m_free(str_find1);
						return ret;
					}
				}
			}
			else if (htonl(*ack_num) != before_ack)
			{	HASH_DEL( my_tcptable, str_find1 );
				m_free(str_find1);
				str_add = (struct my_tcptable_struct*)m_malloc(&rebuild,sizeof(struct my_tcptable_struct));
				if(str_add==NULL)
					return 0;

				memset(str_add->TCP_BIG_DATA, 0x20, TCP_WINDOW);
				memcpy(str_add->hexname, my_ip_port_char, 36);
				pthread_mutex_lock(&mutex);
				str_add->seq_num = htonl(*seq_num);
				str_add->ack_num = htonl(*ack_num);
				str_add->first_seq = str_add->seq_num;
				str_add->tcp_data_len = str_add->seq_num - str_add->first_seq + data_length;
				pthread_mutex_unlock(&mutex);
				if (data_length == 0) {
					return 0;	//already del hash
				}
				memcpy(str_add->TCP_BIG_DATA, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);

				HASH_ADD_STR( my_tcptable, hexname, str_add );

				if ( *(buf_share + pkt_len_share - 5) == 0xfe && (dbtype == 1||dbtype == 4) )	//mysql use 0xfe for end
				{	if (data_length < 4)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;
					}
					else
					{	ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
				else if ( *(buf_share + pkt_len_share - 13) == 0xfd  && *(buf_share + pkt_len_share - 1) == 0x00 && *(buf_share + pkt_len_share - 2) == 0x00 && dbtype == 2 )
				{	if (data_length < 8)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;
					}
					else
					{	ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
				else if ( dbtype == 3 )
				{	if (data_length < 8)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;
					}
					else
					{	ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
				else if ( *(buf_share + pkt_len_share - 1)==0x00 && dbtype == 9 )
				{	if (data_length < 8)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;
					}
					else
					{	ret=proto_analysis(dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, 0, if_custom);
						HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
			}
		}
	} 
	else if (ifack == 1 && ifsyn == 0 && dir == 1)	//visit db
	{
		printf("check_tcp_rebuild, dir = 1\n");
		if (data_length <= 0){
			return 0;	//bad data return
		}
		memcpy(db_mac, buf_share, 6);
		memcpy(visit_mac, buf_share+6, 6);

		HASH_FIND_STR(my_tcptable, my_ip_port_char, str_find1);
		
		if(!str_find1)	//first packet in this session
		{
			str_add = (struct my_tcptable_struct*)m_malloc(&rebuild,sizeof(struct my_tcptable_struct));
			if(str_add==NULL)
				return 0;

			memset(str_add->TCP_BIG_DATA, 0x00, TCP_WINDOW);
			memcpy(str_add->hexname, my_ip_port_char, 36);
			pthread_mutex_lock(&mutex);
			str_add->seq_num = htonl(*seq_num);
			str_add->ack_num = htonl(*ack_num);
			str_add->first_seq = str_add->seq_num;
			str_add->tcp_data_len = data_length;	//if not the firsrt, should be (str_add->seq_num - str_add->first_seq + data_length)
			pthread_mutex_unlock(&mutex);

			if (str_add->tcp_data_len <= 0)
			{	m_free(str_add);	//no HASH_ADD, just free
				return 0;	//bad data return
			}
			memcpy(str_add->TCP_BIG_DATA, buf_share + layer1_len + layer2_ip_len + layer3_tcp_len, data_length);

			if ( (dbtype == 1||dbtype == 4) )
			{	if (data_length < 4)
				{	m_free(str_add);	//no HASH_ADD, just free
					return 0;
				}
				else
				{	int real_data_length = *str_add->TCP_BIG_DATA + (*(str_add->TCP_BIG_DATA+1))*256 + (*(str_add->TCP_BIG_DATA+2))*66536;
					str_add->tcp_data_all_len = real_data_length;
					HASH_ADD_STR( my_tcptable, hexname, str_add );

					if (str_add->tcp_data_all_len > str_add->tcp_data_len)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;	//this packet is the first packet, need to rebuild
					}
					ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
					if (str_add->tcp_data_all_len == (int)(before_length + str_add->seq_num - str_add->first_seq + data_length - 4/*mysql head*/) )
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
			}
			else if ( dbtype == 2 )
			{
				if (data_length < 8)	{
					return 0;
				}
				else
				{	int real_data_length = *(str_add->TCP_BIG_DATA+2)*256 + *(str_add->TCP_BIG_DATA+3);
					str_add->tcp_data_all_len = real_data_length;
					HASH_ADD_STR( my_tcptable, hexname, str_add );
					if (str_add->tcp_data_all_len > str_add->tcp_data_len)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;	//this packet is the first packet, need to rebuild
					}

					ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);

					if (str_add->tcp_data_all_len == data_length)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
			}
			else if ( dbtype == 3 )
			{
				if (data_length < 8)	{
					return 0;
				}
				else
				{	int real_data_length = *(str_add->TCP_BIG_DATA)*256 + *(str_add->TCP_BIG_DATA+1);
					if(real_data_length == 0)
					{
						real_data_length = *(str_add->TCP_BIG_DATA+2)*256 + *(str_add->TCP_BIG_DATA+3);
						//data_add = 2;
					}
					str_add->tcp_data_all_len = real_data_length;
					HASH_ADD_STR( my_tcptable, hexname, str_add );
					if (str_add->tcp_data_all_len > str_add->tcp_data_len)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;	//this packet is the first packet, need to rebuild
					}
					ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);


					if (str_add->tcp_data_all_len == data_length)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
			}
			else if ( dbtype == 9 )		//&& *(buf_share + pkt_len_share)==0x00 
			{	if (*(buf_share + pkt_len_share - 1)==0x00)	{
					str_add->tcp_data_all_len = data_length;
					HASH_ADD_STR( my_tcptable, hexname, str_add );
					proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
					HASH_DEL( my_tcptable, str_add );	
					m_free(str_add);
					return 0;
				}
			//	else	{
			//		str_add->tcp_data_all_len = data_length;
			//		HASH_ADD_STR( my_tcptable, hexname, str_add );
			//		return strategy_info.reset_flag;	//this packet is the first packet, need to rebuild
			//	}
			}
		}
		else if (str_find1)	//have session before
		{
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
				{
					return 0;
				}
				memcpy(str_find1->TCP_BIG_DATA + offset, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);

				str_find1->seq_num = htonl(*seq_num);
				if ( str_find1->tcp_data_all_len = before_length + str_find1->seq_num - first_inside_seq + data_length )
				{	if ( (dbtype == 1||dbtype == 4) && (offset + data_length >= 4 ) ) {
						ret=proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share,tv_sec, buf_share+38, buf_share+42, buf_share, str_find1->tcp_data_all_len, bad_visit, if_custom);
					}
					if ( dbtype == 2 && (offset + data_length >= 8 ) ) {
						ret=proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, str_find1->tcp_data_all_len, bad_visit, if_custom);
					}
					if ( dbtype == 3 && (offset + data_length >= 8 ) ) {
						ret=proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, str_find1->tcp_data_all_len, bad_visit, if_custom);
					}
					if ( dbtype == 9 && (offset + data_length >= 8 ) ) {
						ret=proto_analysis( dir, dbtype, is_compress, str_find1->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, str_find1->tcp_data_all_len, bad_visit, if_custom);
					}
					HASH_DEL( my_tcptable, str_find1 );	
					m_free(str_find1);
					return ret;
				}
			}
			else if (htonl(*ack_num) > before_ack)
			{
				HASH_DEL( my_tcptable, str_find1 );	
				m_free(str_find1);

				str_add = (struct my_tcptable_struct*)m_malloc(&rebuild,sizeof(struct my_tcptable_struct));
				if(str_add==NULL)
					return 0;

				memset(str_add->TCP_BIG_DATA, 0x20, TCP_WINDOW);
				memcpy(str_add->hexname, my_ip_port_char, 36);

				pthread_mutex_lock(&mutex);
				str_add->seq_num = htonl(*seq_num);
				str_add->ack_num = htonl(*ack_num);
				str_add->first_seq = str_add->seq_num;
				str_add->tcp_data_len = str_add->seq_num - str_add->first_seq + data_length;
				pthread_mutex_unlock(&mutex);

				if (data_length == 0)
				{	m_free(str_add);
					return 0;
				}
				memcpy(str_add->TCP_BIG_DATA, buf_share+layer1_len+layer2_ip_len+layer3_tcp_len, data_length);

				HASH_ADD_STR( my_tcptable, hexname, str_add );
				if (str_add->tcp_data_all_len > str_add->tcp_data_len)
				{	HASH_DEL( my_tcptable, str_add );	
					m_free(str_add);
					return 0;	//this packet is the first packet, need to rebuild
				}
				if ( (dbtype == 1||dbtype == 4) )
				{	if (data_length < 4)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;
					}
					else
					{	ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
						HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
				if ( dbtype == 2 )
				{
					if (data_length < 4)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;
					}
					else
					{	ret=proto_analysis(dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
						HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
				if ( dbtype == 3 )
				{	if (data_length < 4)
					{	HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return 0;
					}
					else
					{	ret=proto_analysis(dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
						HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
				if ( dbtype == 9 )
				{	if (data_length < 4)	{
						return 0;
					}
					else
					{	ret=proto_analysis( dir, dbtype, is_compress, str_add->TCP_BIG_DATA, buf_share+26, buf_share+34, buf_share+6, buf_share+30, buf_share+36, buf_share, tv_sec, buf_share+38, buf_share+42, buf_share, data_length, bad_visit, if_custom);
						HASH_DEL( my_tcptable, str_add );	
						m_free(str_add);
						return ret;
					}
				}
			}
		}
	}
	return 0;
}

//输入：数据库类型，方向，数据库协议报文
//返回值：1-报文是完整的，2-不是完整的
//1-mysql, 2-sqlserver, 3-oracle, 4-postgre, 5-sybase, 6-db2, 7-shentong
int if_payload_complete(unsigned char *buf_share,int pkt_len_share,int dir,int db_type){
	if(db_type==1 && dir==1){
		//判断mysql请求报文是否完整
	}else if(db_type==1 && dir==2){
		//判断mysql返回报文是否完整
		if(*(buf_share + pkt_len_share - 5) == 0xfe)
			return 1;
		else
			return 0;
	}else if(db_type==2 && dir==1){
		//判断sqlserver请求报文是否完整
	}else if(db_type==2 && dir==2){
		//判断sqlserver返回报文是否完整
		if(*(buf_share + pkt_len_share-13)==0xfd && *(buf_share + pkt_len_share-1)==0x00 && *(buf_share + pkt_len_share-2)==0x00)
			return 1;
		else
			return 0;
	}else if(db_type==3 && dir==1){
		//判断oracle请求报文是否完整
	}else if(db_type==3 && dir==2){
		//判断oracle返回报文是否完整
		return 1;
	}else if(db_type==4 && dir==1){
		//判断postgre请求报文是否完整
	}else if(db_type==4 && dir==2){
		//判断postgre返回报文是否完整
		if(*(buf_share + pkt_len_share - 5) == 0xfe)
			return 1;
		else
			return 0;
	}else if(db_type==5 && dir==1){
		//判断sybase请求报文是否完整
	}else if(db_type==5 && dir==2){
		//判断sybase返回报文是否完整
	}else if(db_type==6 && dir==1){
		//判断db2请求报文是否完整
	}else if(db_type==6 && dir==2){
		//判断db2返回报文是否完整
	}else if(db_type==7 && dir==1){
		//判断shentong请求报文是否完整
	}else if(db_type==9 && dir==2){
		//判断shentong返回报文是否完整
		if ( *(buf_share + pkt_len_share - 1) == 0x00)
			return 1;
		else
			return 0;
	}
}
