#include <stdio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "head.h"



#ifndef __CHECK_TCP_H__
#define __CHECK_TCP_H__
pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;
int check_tcp_rebuild( int dir, int dbtype, int pkt_len_share, long tv_sec, int if_custom);
						//direction, dbtype, all_len of a packet , time, custom set
#endif