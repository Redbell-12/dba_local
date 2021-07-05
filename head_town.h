#include <stdio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef __HEAD_H__
#define __HEAD_H__

#define TCP_WINDOW 20000
#define OVECCOUNT 30/* should be a multiple of 3 */
#define OPERATE_TYPE 30

#define sql_request 1
#define sql_response 2
#endif


#ifndef __PKT_SEND_H__
#define __PKT_SEND_H__
int pkt_send_body(net_ring *my_txring,uint32_t *my_txring_cur,u_char *buf_tmp,int len);
int pkt_send_reset_data(net_ring *reset_txring,uint32_t *reset_txring_cur,int reset_option,int tcp_len);
#endif

