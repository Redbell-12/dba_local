#ifndef _INTERFACE_H
#define _INTERFACE_H

#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include <sys/socket.h>
#include"./buffer/buffer.h"

typedef struct proto_parser{
	/*判断sql请求报文*/
        int (*is_sql)(u_char *payload);
	/*判断登陆请求报文*/
        int (*is_login)(u_char *payload);
	/*判断登出请求报文*/
        int (*is_logout)(u_char *payload);
	/*判断返回报文*/
        int (*is_response)(u_char *payload);

	/*sql请求报文解析函数*/
        void *(*sql_parse)(u_char *payload,int alllen);
	/*获取风险值函数*/
	int (*get_risk)(u_char *payload,u_char *text,u_char *dst_ip,u_char *dst_port,int bad_visit);
	/*获取风险值函数-如果是登陆失败的返回报文，此函数提供一个风险值*/
	int (*get_risk2)(u_char *payload);
	/*登陆请求报文解析函数*/
        int (*login_parse)(u_char *payload);
	/*登出请求报文解析函数*/
        int (*logout_parse)(u_char *payload);
	/*返回报文解析函数*/
        int (*response_parse)(u_char *payload,buffer *buf);

        buffer *buf;
}proto_parser_t;

/*mysql*/
int mysql_is_sql(u_char *payload);
int mysql_is_login(u_char *payload);
int mysql_is_logout(u_char *payload);
int mysql_is_response(u_char *payload);
void *com_query(u_char * payload,int alllen);
int mysql_get_risk(u_char *payload,u_char *text,u_char *dst_ip,u_char *dst_port,int bad_visit);
int mysql_get_risk2(u_char *payload);
int mysql_response(u_char *payload,buffer *buf);
/*sqlserver*/
int sqlserver_is_sql(u_char *payload);
int sqlserver_is_login(u_char *payload);
int sqlserver_is_logout(u_char *payload);
int sqlserver_is_response(u_char *payload);
void *sqlserver_sql(u_char *payload,int alllen);
int sqlserver_get_risk(u_char *payload,u_char *text,u_char *dst_ip,u_char *dst_port,int bad_visit);
int sqlserver_get_risk2(u_char *payload);
int sqlserver_response(u_char *payload,buffer *buf);
/*oracle*/
int oracle_is_sql(u_char *payload);
int oracle_is_login(u_char *payload);
int oracle_is_logout(u_char *payload);
int oracle_is_response(u_char *payload);
void *oracle_sql(u_char *payload,int alllen);
int oracle_get_risk(u_char *payload,u_char *text,u_char *dst_ip,u_char *dst_port,int bad_visit);
int oracle_get_risk2(u_char *payload);
int oracle_response(u_char *payload,buffer *buf);
/*redis*/
/*postgre*/
int pg_is_sql(u_char *payload);
int pg_is_login(u_char *payload);
int pg_is_logout(u_char *payload);
int pg_is_response(u_char *payload);
void *pg_query(u_char *payload,int alllen);
int pg_get_risk(u_char *payload,u_char *text,u_char *dst_ip,u_char *dst_port,int bad_visit);
int pg_response(u_char *payload,buffer *buf);
/*sybase*/
int sybase_is_sql(u_char *payload);
int sybase_is_login(u_char *payload);
int sybase_is_logout(u_char *payload);
int sybase_is_response(u_char *payload);
void *sybase_sql(u_char *payload,int alllen);
int sybase_get_risk(u_char *payload,u_char *text,u_char *dst_ip,u_char *dst_port,int bad_visit);
int sybase_response(u_char *payload, buffer *buf);
/*db2*/
/*shentong*/
int shentong_is_sql(u_char *payload);
int shentong_is_login(u_char *payload);
int shentong_is_logout(u_char *payload);
int shentong_is_response(u_char *payload);
void *shentong_sql(u_char *payload,int alllen);
int shentong_get_risk(u_char *payload,u_char *text,u_char *dst_ip,u_char *dst_port,int bad_visit);
int shentong_response(u_char *payload, buffer *buf);
/*
extern mysql_buffer;
extern sqlserver_buffer;
extern oracle_buffer;
extern redis_buffer;
extern postgres_buffer;
extern sybase_buffer;
extern db2_buffer;
extern shentong_buffer;
*/
/*数据库类型*/
enum{
	MYSQL,
	SQLSERVER,
	ORACLE,
	REDIS,
	POSTGRE,
	SYBASE,
	DB2,
	SHENTONG
};

int check_if_log(char *text, char *db_ipport);

int log_acknumber(unsigned char *src_ip,unsigned char *src_port,unsigned char *dst_ip,unsigned char *dst_port,unsigned char *ack_number);
int check_acknumber(unsigned char *src_ip,unsigned char *src_port,unsigned char *dst_ip,unsigned char *dst_port,unsigned char *seq_number);

#endif
