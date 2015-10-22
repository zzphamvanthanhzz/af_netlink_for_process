/* 
 * File:   ss_common.h
 * Author: thanhpv
 *
 * Created on October 22, 2015, 2:35 PM
 */

#ifndef SS_COMMON_H
#define	SS_COMMON_H

enum {
	TCP_DB,
	DCCP_DB,
	UDP_DB,
	RAW_DB,
	UNIX_DG_DB,
	UNIX_ST_DB,
	PACKET_DG_DB,
	PACKET_R_DB,
	NETLINK_DB,
	MAX_DB
};
enum
{
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING   /* now a valid state */
};
enum {
	SS_UNKNOWN,
	SS_ESTABLISHED,
	SS_SYN_SENT,
	SS_SYN_RECV,
	SS_FIN_WAIT1,
	SS_FIN_WAIT2,
	SS_TIME_WAIT,
	SS_CLOSE,
	SS_CLOSE_WAIT,
	SS_LAST_ACK,
	SS_LISTEN,
	SS_CLOSING,
	SS_MAX
};

struct ssfilter {
	int type;
	struct ssfilter *post;
	struct ssfilter *pred;
};

struct filter {
	int dbs;
	int states;
	int families;
	struct ssfilter *f;
};
typedef struct {
	unsigned char family;
	unsigned char bytelen;
	__signed__ short bitlen;
	unsigned int flags;
	unsigned int data[8];
} inet_prefix;

struct tcpstat {
	inet_prefix local;
	inet_prefix remote;
	int lport;
	int rport;
	int state;
	int rq, wq;
	int timer;
	int timeout;
	int retrs;
	unsigned ino;
	int probes;
	unsigned uid;
	int refcnt;
	unsigned long long sk;
	int rto, ato, qack, cwnd, ssthresh;
};
#endif	/* SS_COMMON_H */

