#ifndef _FIND_STR_H
#define _FIND_STR_H

extern char *global_response_pr;
extern struct access_ctl_info access_info;

void find_str(char *text,int length,int code_type,char *p);
int find_in_sql(char *payload, char *sql, char *the_ip_port);

//#define ASCII 0
//#define UNICODE 1
enum{ ASCII, UNICODE };

struct access_ctl_info{
	char *sql;/*sql语句*/
	char *the_ip_port;/*ip port*/
	char username[255];/*用户名*/
	char dbname[255];/*库名*/
	char *tbname_array[10];/*表名*/
	int tbname_num;/*表名数量*/
	/*应用程序
	01-LINUX，02-Navicat premium x12，03-Sqlyog，04-WINDOWS Cmd，05-Python，
	06-NAVICAT PREMIUM， 07-sqlplus，08-sql server managet studio，09-Navicat，10-java*/
	int client_type;
	/*操作类型 
	01-select，02-insert，03-update，04-delete，05-truncate，06-create，07-alter，
	08-drop，09-commit，10-grant，11-call，12-desc，13-rename，14-login，15-logout，
	16-begin，17-set，18-use，19-show, */
	int operation_type;
	/*是否有where条件 0-没有，1-有*/
	int if_where;
	/*行数限制line_limit[0]存放起始行号，line_limit[1]存放结束行号*/
	int line_limit[2];
	/*sql语句在原报文中的字节偏移-从零开始计数*/
	int sql_position;
};

#endif
