#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<regex.h>
#include"find_str.h"

/*存放sql语句中防火墙需要的一些信息*/
struct access_ctl_info access_info;

int my_reg_match(char *reg, char *str, regmatch_t match[]);
int sql_lex_syn(char *my_sql);
int access_judge(char *src, char *the_ip_port);

/*
 * 全局指针变量global_response_pr指向返回报文的第一个字节。此指针的设置者为各数据库在解析他们的返回报文的时候
 */
char *global_response_pr;
/*在返回报文中查找某个字符串*/
/*
 * 参数:text指向的length个字符,code_type是字段的编码类型，在sqlserver中，有些字段是unicode编码的，一个字母占两个字节。
 * p是字段在报文中的指针。为什么不直接用text？因为text指向的是字段内容，他有可能是被转码后放到数组中的内容，那么text此时
 * 接受的就是那个数组的指针，不是字段在原报文中的指针了。
 * 功能:比较text字符串和目标字符串是否相同，是的话给出这个字段在整个报文中的偏移-做法是用此字段的指针减整个返回报文的头指针
 */
void find_str(char *text,int length,int code_type, u_char *p)
{
	//printf("%d\n",p-global_response_pr);
	if(code_type==UNICODE){
		//printf("%d\n",length*2);
	}else{
		//printf("%d\n",length);
	}
}

/*在请求语句中找查找一些语义信息，例如库名，表名，where子句等*/
/*返回值是风险值。即原来的check_policy_dba返回值*/
int find_in_sql(char *text, char *the_ip_port){
	/*调用sql_lex_syn(char *my_sql)，分析sql语句，并填充全局变量access_info*/
	sql_lex_syn(text);
	/*接着填充全局变量access_info*/
	access_info.sql=text;
	access_info.the_ip_port=the_ip_port;

printf("sql:%s\n",access_info.sql);
printf("the_ip_port:%s\n",access_info.the_ip_port);
printf("username:%s\n",access_info.username);
printf("dbname:%s\n",access_info.dbname);
printf("tbname:%s\n",access_info.tbname_array[0]);
printf("client:%d\n",access_info.client_type);
printf("operation:%d\n",access_info.operation_type);
printf("where:%d\n",access_info.if_where);
printf("%d:%d\n",access_info.line_limit[0],access_info.line_limit[1]);

	/*调用access_judge(char *src, char *the_ip_port)*/
	int ret=access_judge(text, the_ip_port);

	/*access_judge()返回后立即重置全局变量access_info--将成员tbname_array指向的堆空间释放，然后将变量所有成员归零*/
	int i;
	for(i=0;i<access_info.tbname_num;i++)
		free(access_info.tbname_array[i]);
	memset(&access_info,0,sizeof(struct access_ctl_info));

	return ret;
}
int my_reg_match(char *reg, char *str, regmatch_t match[]){
	regex_t r;
	//注意，在c语言中双反斜杠才表示一个普通的反斜杠，所以双反斜杠星才表示一个普通的
	//反斜杠星，进而regcomp函数才将反斜杠星解释为普通的星。你若只有一个反斜杠星，则
	//c编译器这边就过不去，c编译器不知道将单反斜杠星解释成什么

	//下面两个函数成功返回0，失败非0
	int ret=0;
	if(ret=regcomp(&r, reg, REG_ICASE|REG_EXTENDED)){
		char buf[255]={0};
		regerror(ret, NULL, buf, 254);
		fprintf(stderr, "regcomp:%s\n", buf);
		return -1;
	}

	if(ret=regexec(&r, str, 1, match, REG_NOTBOL)){
		return -1;
	}else{//成功
		return 0;
	}
}

