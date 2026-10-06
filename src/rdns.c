#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

#include "rdns.h"
#include "allocator_thread.h"
#include "remotedns.h"

#ifndef HAVE_SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

//static enum dns_lookup_flavor dns_flavor;
#define dns_flavor rdns_get_flavor()

static struct sockaddr_in rdns_server;

static ssize_t rdns_daemon_exchange(struct at_msg *msg, size_t len) {
	int fd = socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, 0);
	ssize_t ret = -1;
	if(fd == -1) return -1;
	if(connect(fd, (void*)&rdns_server, sizeof(rdns_server))) goto out;
	if(send(fd, msg, len, 0) != (ssize_t) len) goto out;
	ret = recv(fd, msg, sizeof(*msg), 0);
out:
	close(fd);
	return ret;
}

size_t rdns_daemon_get_host_for_ip(ip_type4 ip, char* readbuf) {
	struct at_msg msg = {
		.h.msgtype = ATM_GETNAME,
		.h.datalen = htons(4),
		.m.ip = ip,
	};
	ssize_t received = rdns_daemon_exchange(&msg, sizeof(msg.h)+4);
	if(received < (ssize_t) sizeof(msg.h) || msg.h.msgtype != ATM_GETNAME) return 0;
	msg.h.datalen = ntohs(msg.h.datalen);
	if(!msg.h.datalen || msg.h.datalen > MSG_LEN_MAX ||
	   received != (ssize_t) (sizeof(msg.h)+msg.h.datalen) ||
	   memchr(msg.m.host, 0, msg.h.datalen) != &msg.m.host[msg.h.datalen-1]) return 0;
	memcpy(readbuf, msg.m.host, msg.h.datalen);
	return msg.h.datalen - 1;
}

static ip_type4 rdns_daemon_get_ip_for_host(char* host, size_t len) {
	struct at_msg msg = {
		.h.msgtype = ATM_GETIP,
	};
	if(len >= 256) return IPT4_INT(-1);
	memcpy(msg.m.host, host, len+1);
	msg.h.datalen = htons(len+1);
	ssize_t received = rdns_daemon_exchange(&msg, sizeof(msg.h)+len+1);
	if(received != (ssize_t) (sizeof(msg.h)+sizeof(ip_type4)) ||
	   msg.h.msgtype != ATM_GETIP || ntohs(msg.h.datalen) != sizeof(ip_type4))
		return IPT4_INT(-1);
	return msg.m.ip;
}

const char *rdns_resolver_string(enum dns_lookup_flavor flavor) {
	static const char tab[][7] = {
		[DNSLF_LIBC] = "off",
		[DNSLF_FORKEXEC] = "old",
		[DNSLF_RDNS_THREAD] = "thread",
		[DNSLF_RDNS_DAEMON] = "daemon",
	};
	return tab[flavor];
}

void rdns_init(enum dns_lookup_flavor flavor) {
	static int init_done = 0;
	if(!init_done) switch(flavor) {
		case DNSLF_RDNS_THREAD:
			at_init();
			break;
		case DNSLF_RDNS_DAEMON:
		default:
			break;
	}
	init_done = 1;
}

void rdns_set_daemon(struct sockaddr_in* addr) {
	rdns_server = *addr;
}

#if 0
enum dns_lookup_flavor rdns_get_flavor(void) {
	return dns_flavor;
}
#endif

size_t rdns_get_host_for_ip(ip_type4 ip, char* readbuf) {
	switch(dns_flavor) {
		case DNSLF_RDNS_THREAD: return at_get_host_for_ip(ip, readbuf);
		case DNSLF_RDNS_DAEMON: return rdns_daemon_get_host_for_ip(ip, readbuf);
		default:
			abort();
	}
}

ip_type4 rdns_get_ip_for_host(char* host, size_t len) {
	switch(dns_flavor) {
		case DNSLF_RDNS_THREAD: return at_get_ip_for_host(host, len);
		case DNSLF_RDNS_DAEMON: return rdns_daemon_get_ip_for_host(host, len);
		default:
			abort();
	}
}
