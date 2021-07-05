#include "interface.h"

//解析器数组
//0-mysql, 1-sqlserver, 2-oracle, 3-postgre, 4-sybase, 5-db2, 6-shentong
proto_parser_t parsers[7]={
    	/*mysql*/
	{mysql_is_sql, mysql_is_login, mysql_is_logout, mysql_is_response,
	 com_query, mysql_get_risk, mysql_get_risk2, NULL, NULL, mysql_response, &mysql_buffer},
	/*sqlserver*/
	{sqlserver_is_sql, sqlserver_is_login, sqlserver_is_logout, sqlserver_is_response,
	 sqlserver_sql, sqlserver_get_risk, sqlserver_get_risk2, NULL, NULL, sqlserver_response, &sqlserver_buffer},
	/*oracle*/
	{oracle_is_sql, oracle_is_login, oracle_is_logout, oracle_is_response,
	 oracle_sql, oracle_get_risk, oracle_get_risk2, NULL, NULL, oracle_response, &oracle_buffer},
	/*postgre*/
	{pg_is_sql, pg_is_login, pg_is_logout, pg_is_response,
	 pg_query, pg_get_risk, NULL, NULL, NULL, pg_response, &postgres_buffer},
	/*sybase*/
	{sybase_is_sql, sybase_is_login, sybase_is_logout, NULL,
	 sybase_sql, sybase_get_risk, NULL, NULL, NULL, sybase_response, &sybase_buffer},
	/*db2*/
	{/*NULL,NULL,NULL,NULL,
	 db2_sql,NULL,NULL,NULL, NULL, db2_response, &db2_buffer*/},
	/*shentong*/
	{shentong_is_sql, shentong_is_login, shentong_is_logout, NULL,
	 shentong_sql, shentong_get_risk, NULL, NULL, NULL, shentong_response, &shentong_buffer}
};
void proto_analysis(int dir, int db_type, int is_compress, u_char *payload, u_char *src_ip, u_char *src_port, u_char *src_mac,
		    u_char *dst_ip, u_char *dst_port, u_char *dst_mac, long op_time, u_char *seq_number, u_char *ack_number,
		    u_char *buf_pack, int alllen, int bad_visit, int if_custom)
{
	//根据数据库类型选择解析器
	proto_parser_t parser=parsers[db_type];

	u_char array[100];
	int n;
	/*根据方向和类型解析报文*/
	if(dir==1){
		if(parser.is_sql!=NULL && parser.is_sql(payload)){//sql语句
			/*解析sql语句*/
			u_char *text=parser.sql_parse(payload,alllen);
			if(text==NULL)
				return;

			if(if_custom==1){
				char db_ipport[12+1];
				snprintf(db_ipport,13,"%02x%02x%02x%02x%02x%02x",dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3],dst_port[0],dst_port[1]);
				if(check_if_log(text, db_ipport)){
					//把不用记录的报文的ack记录下来，如果某个返回报文的seq与这里
					//记录的ack相等，则那个返回报文也不用记录
					log_acknumber(src_ip,src_port,dst_ip,dst_port,ack_number);
					return;
				}
			}

			/*输出格式头*/
			out_header(parser.buf,op_time,src_ip,src_port,src_mac,dst_ip,dst_port,dst_mac,db_type,dir,is_compress);
			/*用户名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*数据库名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*表名*/
			print_buf("0|||",strlen("0|||"),parser.buf);

			/*判断操作类型（sql语句首单词）是否合法*/
			int legal=is_legal(text,strlen(text),0);
                        /*首单词转大写并写入缓冲区*/
                        print_firstword(legal,text,0,parser.buf);
                        /*响应*/
                        print_buf("|||0|||",strlen("|||0|||"),parser.buf);

			//动态获取风险值
			int risk=parser.get_risk(payload,text,dst_ip,dst_port,bad_visit);
			n=sprintf(array,"%03d",risk);
			array[n]='\0';
			strcat(array,"|||");
			/*风险*/
			print_buf(array,strlen(array),parser.buf);

			/*4个字段0*/
			print_buf("0|||0|||0|||0|||",strlen("0|||0|||0|||0|||"),parser.buf);
			/*输出整个sql语句到缓冲区*/
			print_buf(text,strlen(text),parser.buf);
			free(text);

			//换行
			print_buf("\n",strlen("\n"),parser.buf);

			//如果risk的值大于0小于100，则表示本请求被防火墙挡掉了，则我们立即再往buffer中写一条表示请求失败的返回记录
			if(risk>0 && risk<100){
				/*输出格式头*/
				out_header(parser.buf,op_time,src_ip,src_port,src_mac,dst_ip,dst_port,dst_mac,db_type,2/*方向*/,is_compress);

				/*用户名*/
				print_buf("0|||",strlen("0|||"),parser.buf);
				/*数据库名*/
				print_buf("0|||",strlen("0|||"),parser.buf);
				/*表名*/
				print_buf("0|||",strlen("0|||"),parser.buf);
				/*操作*/
				print_buf("RESPONSE|||",strlen("RESPONSE|||"),parser.buf);	
				/*响应*/
				print_buf("0|||",strlen("0|||"),parser.buf);

				//风险值
				n=sprintf(array,"%03d",risk);
				array[n]='\0';
				strcat(array,"|||");
				/*风险*/
				print_buf(array,strlen(array),parser.buf);

				/*4个字段0*/
				print_buf("0|||0|||0|||0|||",strlen("0|||0|||0|||0|||"),parser.buf);

				print_buf("\n",strlen("\n"),parser.buf);	
			}
				
		}else if(parser.is_login!=NULL && parser.is_login(payload)){//登陆
			/*输出格式头*/
			out_header(parser.buf,op_time,src_ip,src_port,src_mac,dst_ip,dst_port,dst_mac,db_type,dir,is_compress);
			
			/*用户名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*数据库名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*表名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*操作*/
			print_buf("LOGIN|||",strlen("LOGIN|||"),parser.buf);
			/*响应*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*风险*/
			print_buf("1|||",strlen("1|||"),parser.buf);
			/*4个字段0*/
			print_buf("0|||0|||0|||0|||",strlen("0|||0|||0|||0|||"),parser.buf);
			/*输出最后部分*/
                        print_buf("login:",strlen("login:"),parser.buf);

			print_buf("\n",strlen("\n"),parser.buf);
		}else if(parser.is_logout!=NULL && parser.is_logout(payload)){//登出
			/*输出格式头*/
			out_header(parser.buf,op_time,src_ip,src_port,src_mac,dst_ip,dst_port,dst_mac,db_type,dir,is_compress);
			
			/*用户名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*数据库名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*表名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*操作*/
			print_buf("LOGOUT|||",strlen("LOGOUT|||"),parser.buf);
			/*响应*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*风险*/
			print_buf("1|||",strlen("1|||"),parser.buf);
			/*4个字段0*/
                        print_buf("0|||0|||0|||0|||",strlen("0|||0|||0|||0|||"),parser.buf);
			/*输出最后部分*/
                        print_buf("logout:",strlen("logout:"),parser.buf);

			print_buf("\n",strlen("\n"),parser.buf);
		}
	}else if(dir==2){
		if(parser.is_response!=NULL && parser.is_response(payload)){
			if(check_acknumber(src_ip,src_port,dst_ip,dst_port,seq_number))
				return;
			/*输出格式头*/
			out_header(parser.buf,op_time,src_ip,src_port,src_mac,dst_ip,dst_port,dst_mac,db_type,dir,is_compress);

			/*用户名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*数据库名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*表名*/
			print_buf("0|||",strlen("0|||"),parser.buf);
			/*操作*/
			print_buf("RESPONSE|||",strlen("RESPONSE|||"),parser.buf);	
			/*响应*/
			print_buf("0|||",strlen("0|||"),parser.buf);

			//动态获取风险值
			int risk=parser.get_risk2(payload);
			n=sprintf(array,"%03d",risk);
			array[n]='\0';
			strcat(array,"|||");
			/*风险*/
			print_buf(array,strlen(array),parser.buf);

			/*4个字段0*/
			print_buf("0|||0|||0|||0|||",strlen("0|||0|||0|||0|||"),parser.buf);
			/*输出整个返回*/
			parser.response_parse(payload,parser.buf);

			print_buf("\n",strlen("\n"),parser.buf);	
		}
	}
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

int log_acknumber(unsigned char *src_ip,unsigned char *src_port,unsigned char *dst_ip,unsigned char *dst_port,unsigned char *ack_number){
	request[ack_i % 100].flag=1;
	request[ack_i % 100].src_ip=*(unsigned int *)src_ip;
	request[ack_i % 100].src_port=*(unsigned short *)src_port;
	request[ack_i % 100].dst_ip=*(unsigned int *)dst_ip;
	request[ack_i % 100].dst_port=*(unsigned short *)dst_port;
	request[ack_i % 100].ack_number=*(unsigned int *)ack_number;
	ack_i++;
}

int check_acknumber(unsigned char *src_ip,unsigned char *src_port,unsigned char *dst_ip,unsigned char *dst_port,unsigned char *seq_number){
	int i;
	for(i=0;i<100;i++){
		if(request[i].flag != 0 &&
		   request[i].src_ip==*(unsigned int *)dst_ip &&
		   request[i].src_port==*(unsigned short *)dst_port &&
		   request[i].dst_ip==*(unsigned int *)src_ip &&
		   request[i].dst_port==*(unsigned short *)src_port &&
		   request[i].ack_number==*(unsigned int *)seq_number){
			request[i].flag = 0;//将匹配到的数组项置为无效
			return 1;
		}
	}
	return 0;
}
