#include <stdio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "head.h"


#ifndef __FILE_CONF_H__
#define __FILE_CONF_H__

/*
extern struct access_ctl_info access_info;
extern access_rule_struct *access_head;
extern access_rule_struct *access_elt;
extern dba_policy_struct *policy_head;
extern dba_policy_struct *policy_elt;
*/
int dba_config_insert(FILE * pFile);
int dba_policy_insert(FILE * pFile);
int access_rule_insert(FILE * pFile);
int value_mask_insert(FILE * pFile);
void* dba_config_process();	//basic config file read
void* dba_policy_process();
void* access_rule_process();
void* value_mask_process(void *arg);	//mask config file read
#endif