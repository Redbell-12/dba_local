#ifndef __ACCESS_JUDGE_H__
#define __ACCESS_JUDGE_H__

#include <stdio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "head.h"
//#include "find_str.h"
#include "headfile/find_str/find_str.h"

//extern char strategy_number[37] ;

int check_policy_dba( char *src, char* the_ip_port);
int check_value_mask(char *the_ip_port);
int access_check_user_name(char* the_ip_port, char *user_name);
int access_check_db_name(char* the_ip_port, char *db_name);
int access_check_table_name(char* the_ip_port, char *tbname_array);
int access_check_client_type(char* the_ip_port, int client_type);
int access_check_operate_type(char* the_ip_port, int operate_type);
int access_check_where(char* the_ip_port, int where);
int access_check_line(char* the_ip_port, int line1, int line2);
int access_judge( char *src, char* the_ip_port, struct access_ctl_info access_info);
#endif
