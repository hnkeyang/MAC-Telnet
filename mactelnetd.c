/*
	Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
	Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>

	Shameless hack by Ali Onur Uyar to add support for SSH Tunneling through
	MAC-Telnet protocol.
	Copyright (C) 2011, Ali Onur Uyar <aouyar@gmail.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#define _XOPEN_SOURCE 600
#define _BSD_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <endian.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <pwd.h>
#include <utmp.h>
#include <syslog.h>
#include <sys/utsname.h>

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include <libubox/md5.h>

#include "protocol.h"
#include "console.h"
#include "interfaces.h"
#include "users.h"
#include "config.h"

#define PROGRAM_NAME "MAC-Telnet Daemon"

/* Max ~5 pings per second */
#define MT_MAXPPS MT_MNDP_BROADCAST_INTERVAL * 5

static int sockfd;

static int pings = 0;

static int tunnel_conn = 0;
static char nonpriv_username[255];
static char exec_command[256] = {0};

static struct in_addr sourceip = { INADDR_ANY };
static struct in_addr destip = { INADDR_BROADCAST };
static int fwdport = MT_TUNNEL_SERVER_PORT;

static time_t last_mndp_time = 0;

/* Protocol data direction */
uint8_t mt_direction_fromserver = 1;

/* Anti-timeout is every 10 seconds. Give up after 15. */
#define MT_CONNECTION_TIMEOUT 15

/* Connection states */
enum mt_connection_state {
	STATE_AUTH,
	STATE_CLOSED,
	STATE_ACTIVE
};

/** Connection struct */
struct mt_connection {
	struct net_interface *interface;
	char interface_name[IFNAMSIZ];

	uint16_t seskey;
	uint32_t incounter;
	uint32_t outcounter;

	enum mt_connection_state state;
	int wait_for_ack;

	struct in_addr srcip;
	struct ether_addr srcmac;
	uint16_t srcport;
	struct ether_addr dstmac;
	uint8_t enckey[16];

#ifdef TELNET_SUPPORT
	int have_enckey;
	int slavefd;
	char username[30];
	int terminal_mode;
	char terminal_type[30];
	uint8_t trypassword[17];
	uint16_t terminal_width;
	uint16_t terminal_height;
#endif

	struct list_head list;

	struct uloop_timeout timeout;
	struct uloop_fd socket;
};

static LIST_HEAD(connections);

static void list_remove_connection(struct mt_connection *conn) {
	uloop_fd_delete(&conn->socket);
	uloop_timeout_cancel(&conn->timeout);

	if ( conn->state == STATE_ACTIVE && conn->socket.fd > 0) {
		close(conn->socket.fd);
	}

#ifdef TELNET_SUPPORT
	if (!tunnel_conn && conn->state == STATE_ACTIVE && conn->slavefd > 0) {
		close(conn->slavefd);
	}
#endif

	list_del(&conn->list);

	free(conn);
}

static struct mt_connection *list_find_connection(uint16_t seskey, struct ether_addr *srcmac) {
	struct mt_connection *p;

	list_for_each_entry(p, &connections, list)
		if (p->seskey == seskey && memcmp(srcmac, &p->srcmac, ETH_ALEN) == 0)
			return p;

	return NULL;
}

static int send_udp(const struct mt_connection *conn, const struct mt_packet *packet) {
	return net_send_udp(sockfd, conn->interface, &conn->dstmac, &conn->srcmac, &sourceip, MT_MACTELNET_PORT, &destip, conn->srcport, packet->data, packet->size);
}

static int send_special_udp(struct net_interface *interface, uint16_t port, const struct mt_packet *packet) {
	struct ether_addr dstmac;
	memset(&dstmac, 0xFF, ETH_ALEN);
	return net_send_udp(sockfd, interface, &interface->mac_addr, &dstmac, &interface->ipv4_addr, port, &destip, port, packet->data, packet->size);
}

static void abort_connection(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr, char *message) {
	struct mt_packet pdata;

	init_packet(&pdata, MT_PTYPE_DATA, &pkthdr->dstaddr, &pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, message, strlen(message));
	send_udp(curconn, &pdata);

	/* Make connection time out; lets the previous message get acked before disconnecting */
	curconn->state = STATE_CLOSED;
	init_packet(&pdata, MT_PTYPE_END, &pkthdr->dstaddr, &pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	send_udp(curconn, &pdata);
}


#ifdef TELNET_SUPPORT
static void display_banner() {
	FILE *fp;
	int c;

	if ((fp = fopen("/etc/banner", "r"))) {
		while ((c = getc(fp)) != EOF) {
			putchar(c);
		}
		fclose(fp);
	}
}

static void user_login(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr) {
	struct mt_packet pdata;
	uint8_t md5sum[17];
	char md5data[100];
	struct mt_credentials *user;
	char *slavename;
	md5_ctx_t md5;

	/* Reparse user file before each login */
	if (exec_command[0] == '\0')
		read_userfile();

	if ((user = find_user(curconn->username)) != NULL) {
		/* Concat string of 0 + password + encryptionkey */
		md5data[0] = 0;
		strncpy(md5data + 1, user->password, 82);
		memcpy(md5data + 1 + strlen(user->password), curconn->enckey, 16);

		/* Generate md5 sum of md5data with a leading 0 */
		md5_begin(&md5);
		md5_hash(md5data, strlen(user->password) + 17, &md5);
		md5_end(md5sum + 1, &md5);
		md5sum[0] = 0;

		init_packet(&pdata, MT_PTYPE_DATA, &pkthdr->dstaddr, &pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
		curconn->outcounter += add_control_packet(&pdata, MT_CPTYPE_END_AUTH, NULL, 0);
		send_udp(curconn, &pdata);

		if (curconn->state == STATE_ACTIVE) {
			return;
		}
	}

	if (user == NULL || memcmp(md5sum, curconn->trypassword, 17) != 0) {
		syslog(LOG_NOTICE, "(%d) Invalid login by %s.", curconn->seskey, curconn->username);

		/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
		abort_connection(curconn, pkthdr, "Login failed, incorrect username or password\r\n");

		/* TODO: should wait some time (not with sleep) before returning, to minimalize brute force attacks */
		return;
	}

	/* User is logged in */
	curconn->state = STATE_ACTIVE;

	/* Enter terminal mode */
	curconn->terminal_mode = 1;

	/* Open pts handle */
	curconn->socket.fd = posix_openpt(O_RDWR);
	if (curconn->socket.fd == -1 || grantpt(curconn->socket.fd) == -1 || unlockpt(curconn->socket.fd) == -1) {
			syslog(LOG_ERR, "posix_openpt: %s", strerror(errno));
			/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
			abort_connection(curconn, pkthdr, "Terminal error\r\n");
			return;
	}

	/* Get file path for our pts */
	slavename = ptsname(curconn->socket.fd);
	if (slavename != NULL) {
		struct passwd *user = (struct passwd *)getpwnam(curconn->username);
		if (user == NULL) {
			syslog(LOG_WARNING, "(%d) Login ok, but local user not accessible (%s).", curconn->seskey, curconn->username);
			/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
			abort_connection(curconn, pkthdr, "Local user not accessible\r\n");
			return;
		}

		/* Change the owner of the slave pts */
		chown(slavename, user->pw_uid, user->pw_gid);

		curconn->slavefd = open(slavename, O_RDWR);
		if (curconn->slavefd == -1) {
			syslog(LOG_ERR, "Error opening %s: %s", slavename, strerror(errno));
			/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
			abort_connection(curconn, pkthdr, "Error opening terminal\r\n");
			list_remove_connection(curconn);
			return;
		}

		if (fork() == 0) {
			syslog(LOG_INFO, "(%d) User %s logged in.", curconn->seskey, curconn->username);

			uloop_done();

			/* Initialize terminal environment */
			setenv("USER", user->pw_name, 1);
			setenv("HOME", user->pw_dir, 1);
			setenv("SHELL", user->pw_shell, 1);
			setenv("TERM", curconn->terminal_type, 1);
			close(sockfd);

			setsid();

			/* Don't let shell process inherit slavefd */
			fcntl (curconn->slavefd, F_SETFD, FD_CLOEXEC);
			close(curconn->socket.fd);

			/* Redirect STDIN/STDIO/STDERR */
			close(0);
			dup(curconn->slavefd);
			close(1);
			dup(curconn->slavefd);
			close(2);
			dup(curconn->slavefd);

			/* Set controlling terminal */
			ioctl(0, TIOCSCTTY, 1);
			tcsetpgrp(0, getpid());

			/* Set user id/group id */
			if ((setgid(user->pw_gid) != 0) || (setuid(user->pw_uid) != 0)) {
				syslog(LOG_ERR, "(%d) Could not log in %s (%d:%d): setuid/setgid: %s", curconn->seskey, curconn->username, user->pw_uid, user->pw_gid, strerror(errno));
				/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
				abort_connection(curconn, pkthdr, "Internal error\r\n");
				exit(0);
			}

			/* Display MOTD */
			display_banner();

			chdir(user->pw_dir);

			/* Spawn shell or execute command */
			if (exec_command[0] != '\0') {
				/* Execute specified command instead of shell */
				execl("/bin/sh", "/bin/sh", "-c", exec_command, (char *) 0);
			} else {
				/* TODO: Maybe use "login -f USER" instead? renders motd and executes shell correctly for system */
				execl(user->pw_shell, user->pw_shell, "-", (char *) 0);
			}
			exit(0); // just to be sure.
		}

		close(curconn->slavefd);
		set_terminal_size(curconn->socket.fd, curconn->terminal_width, curconn->terminal_height);
	}

	uloop_fd_add(&curconn->socket, ULOOP_READ | ULOOP_ERROR_CB);
}
#endif

#ifdef TELNET_SUPPORT
static void exec_command_direct(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr) {
	struct mt_packet pdata;
	char *slavename;

	/* Send END_AUTH to client */
	init_packet(&pdata, MT_PTYPE_DATA, &pkthdr->dstaddr, &pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	curconn->outcounter += add_control_packet(&pdata, MT_CPTYPE_END_AUTH, NULL, 0);
	send_udp(curconn, &pdata);

	if (curconn->state == STATE_ACTIVE) {
		return;
	}

	/* User is logged in */
	curconn->state = STATE_ACTIVE;

	/* Enter terminal mode */
	curconn->terminal_mode = 1;

	/* Open pts handle */
	curconn->socket.fd = posix_openpt(O_RDWR);
	if (curconn->socket.fd == -1 || grantpt(curconn->socket.fd) == -1 || unlockpt(curconn->socket.fd) == -1) {
		syslog(LOG_ERR, "posix_openpt: %s", strerror(errno));
		abort_connection(curconn, pkthdr, "Terminal error\r\n");
		return;
	}

	/* Get file path for our pts */
	slavename = ptsname(curconn->socket.fd);
	if (slavename != NULL) {
		curconn->slavefd = open(slavename, O_RDWR);
		if (curconn->slavefd == -1) {
			syslog(LOG_ERR, "Error opening %s: %s", slavename, strerror(errno));
			abort_connection(curconn, pkthdr, "Error opening terminal\r\n");
			list_remove_connection(curconn);
			return;
		}

		if (fork() == 0) {
			syslog(LOG_INFO, "(%d) Executing command: %s", curconn->seskey, exec_command);

			uloop_done();

			/* Initialize terminal environment */
			setenv("USER", "nobody", 1);
			setenv("HOME", "/", 1);
			setenv("SHELL", "/bin/sh", 1);
			setenv("TERM", curconn->terminal_type[0] ? curconn->terminal_type : "xterm", 1);
			close(sockfd);

			setsid();

			/* Don't let shell process inherit slavefd */
			fcntl(curconn->slavefd, F_SETFD, FD_CLOEXEC);
			close(curconn->socket.fd);

			/* Redirect STDIN/STDIO/STDERR */
			close(0);
			dup(curconn->slavefd);
			close(1);
			dup(curconn->slavefd);
			close(2);
			dup(curconn->slavefd);

			/* Set controlling terminal */
			ioctl(0, TIOCSCTTY, 1);
			tcsetpgrp(0, getpid());

			/* Execute the command */
			execl("/bin/sh", "/bin/sh", "-c", exec_command, (char *) 0);
			exit(0);
		}

		close(curconn->slavefd);
		set_terminal_size(curconn->socket.fd, curconn->terminal_width, curconn->terminal_height);
	}

	uloop_fd_add(&curconn->socket, ULOOP_READ | ULOOP_ERROR_CB);
}
#endif

static void setup_tunnel(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr) {
	struct mt_packet pdata;
	char port[sizeof("65535\0")];
	int optval = 1;

	init_packet(&pdata, MT_PTYPE_DATA, &pkthdr->dstaddr, &pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	curconn->outcounter += add_control_packet(&pdata, MT_CPTYPE_END_AUTH, NULL, 0);
	send_udp(curconn, &pdata);

	if (curconn->state == STATE_ACTIVE)
		return;

	/* Setup socket for connecting tunnel to server port. */
	snprintf(port, sizeof(port), "%d", fwdport);
	curconn->socket.fd = usock(USOCK_TCP|USOCK_IPV4ONLY|USOCK_NUMERIC, "127.0.0.1", port);

	if (curconn->socket.fd < 0) {
		syslog(LOG_ERR, "Error in connection of tunnel to server port: %s", strerror(errno));
		abort_connection(curconn, pkthdr, "Error in connection of tunnel to server.\r\n");
		return;
	}

	if (setsockopt(curconn->socket.fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
		syslog(LOG_ERR, "Error in setting SO_KEEPALIVE option for socket: %s", strerror(errno));
		abort_connection(curconn, pkthdr, "Socket error.\r\n");
		return;
	}

	/* User is logged in */
	curconn->state = STATE_ACTIVE;
	uloop_fd_add(&curconn->socket, ULOOP_READ);
}

#ifdef TELNET_SUPPORT
static void send_challange(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr) {
	int i;
	struct mt_packet pdata;

	if (!curconn->have_enckey)
	{
		for (i = 0; i < 16; ++i)
			curconn->enckey[i] = rand() % 256;

		curconn->have_enckey = 1;
		memset(curconn->trypassword, 0, sizeof(curconn->trypassword));
	}

	init_packet(&pdata, MT_PTYPE_DATA, &pkthdr->dstaddr, &pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	curconn->outcounter += add_control_packet(&pdata, MT_CPTYPE_ENCRYPTIONKEY, (curconn->enckey), 16);

	send_udp(curconn, &pdata);
}
#endif

static void handle_data_packet(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr, int data_len) {
	struct mt_mactelnet_control_hdr cpkt;
	uint8_t *data = pkthdr->data;
	int success;

#ifdef TELNET_SUPPORT
	int got_user_packet = 0;
	int got_pass_packet = 0;
	int got_size_packet = 0;
	uint16_t width;
	uint16_t height;
#endif

	/* Parse first control packet */
	success = parse_control_packet(data, data_len - MT_HEADER_LEN, &cpkt);

	while (success)
	{
		switch (cpkt.cptype)
		{
		case MT_CPTYPE_BEGINAUTH:
			if (tunnel_conn)
				setup_tunnel(curconn, pkthdr);
#ifdef TELNET_SUPPORT
			else if (exec_command[0] != '\0')
				exec_command_direct(curconn, pkthdr);
			else
				send_challange(curconn, pkthdr);
#endif
			break;

		case MT_CPTYPE_TERM_WIDTH:
			if (tunnel_conn)
				goto require_ssh;
#ifdef TELNET_SUPPORT
			memcpy(&width, cpkt.data, 2);
			curconn->terminal_width = le16toh(width);
			got_size_packet = (curconn->state == STATE_ACTIVE);
#endif
			break;

		case MT_CPTYPE_TERM_HEIGHT:
			if (tunnel_conn)
				goto require_ssh;
#ifdef TELNET_SUPPORT
			memcpy(&height, cpkt.data, 2);
			curconn->terminal_height = le16toh(height);
			got_size_packet = (curconn->state == STATE_ACTIVE);
#endif
			break;

		case MT_CPTYPE_TERM_TYPE:
			if (tunnel_conn)
				goto require_ssh;
#ifdef TELNET_SUPPORT
			memcpy(curconn->terminal_type, cpkt.data, cpkt.length > 29 ? 29 : cpkt.length);
			curconn->terminal_type[cpkt.length > 29 ? 29 : cpkt.length] = 0;
#endif
			break;

		case MT_CPTYPE_USERNAME:
			if (tunnel_conn)
				goto require_ssh;
#ifdef TELNET_SUPPORT
			memcpy(curconn->username, cpkt.data, cpkt.length > 29 ? 29 : cpkt.length);
			curconn->username[cpkt.length > 29 ? 29 : cpkt.length] = 0;
			got_user_packet = 1;
#endif
			break;

		case MT_CPTYPE_PASSWORD:
			if (tunnel_conn)
				goto require_ssh;
#ifdef TELNET_SUPPORT
			memcpy(curconn->trypassword, cpkt.data, 17);
			got_pass_packet = 1;
#endif
			break;

		case MT_CPTYPE_PLAINDATA:
			/* relay data from client to shell/tunnel */
			if (curconn->state == STATE_ACTIVE && curconn->socket.fd != -1) {
				if (write(curconn->socket.fd, cpkt.data, cpkt.length) <= 0 && tunnel_conn) {
					syslog(LOG_INFO, "(%d) Connection from tunnel to server port closed.", curconn->seskey);
					abort_connection(curconn, pkthdr, "Server port disconnection.\r\n");
					return;
				}
			}
			break;

		default:
			syslog(LOG_WARNING, "(%d) Unhandeled control packet type: %d", curconn->seskey, cpkt.cptype);
		}

		/* Parse next control packet */
		success = parse_control_packet(NULL, 0, &cpkt);
	}

#ifdef TELNET_SUPPORT
	if (got_user_packet && got_pass_packet)
		user_login(curconn, pkthdr);

	if (got_size_packet)
		set_terminal_size(curconn->socket.fd, curconn->terminal_width, curconn->terminal_height);
#endif

	return;

require_ssh:
	syslog(LOG_INFO, "(%d) Connection from tunnel to server port closed.", curconn->seskey);
	abort_connection(curconn, pkthdr, "The server does not support standard MAC-Telnet Protocol. Please try using MAC-SSH instead.\r\n");
}

static void recv_bulk(struct uloop_fd *ufd, uint32_t ev);
static void timeout_session(struct uloop_timeout *utm);

static void handle_packet(struct mt_mactelnet_hdr *pkt, struct sockaddr_in *src, int data_len, int in_ifindex) {
	struct mt_connection *curconn = NULL;
	struct mt_packet pdata;
	struct net_interface *iface;

	/* Drop packets not belonging to us */
	if ((iface = net_ifaces_lookup_ifindex(&pkt->dstaddr, in_ifindex)) == NULL)
		return;

	switch (pkt->ptype)
	{
		case MT_PTYPE_PING:
			if (pings++ > MT_MAXPPS)
				break;

			init_pongpacket(&pdata, &pkt->dstaddr, &pkt->srcaddr);
			add_packetdata(&pdata, pkt->data - 4, data_len - (MT_HEADER_LEN - 4));
			send_special_udp(iface, MT_MACTELNET_PORT, &pdata);
			break;

		case MT_PTYPE_SESSIONSTART:
			syslog(LOG_DEBUG, "(%d) New connection from %s.", pkt->seskey, ether_ntoa((struct ether_addr*)&(pkt->srcaddr)));

			curconn = calloc(1, sizeof(*curconn));
			if (!curconn)
				break;

			curconn->seskey = pkt->seskey;
			curconn->state = STATE_AUTH;
			curconn->interface = iface;
			strncpy(curconn->interface_name, iface->name, sizeof(curconn->interface_name) - 1);
			curconn->srcmac = pkt->srcaddr;
			curconn->srcip = src->sin_addr;
			curconn->srcport = htons(src->sin_port);
			curconn->dstmac = pkt->dstaddr;

			curconn->socket.cb = recv_bulk;
			curconn->timeout.cb = timeout_session;

			list_add_tail(&curconn->list, &connections);
			uloop_timeout_set(&curconn->timeout, MT_CONNECTION_TIMEOUT * 1000);

			init_packet(&pdata, MT_PTYPE_ACK, &pkt->dstaddr, &pkt->srcaddr, pkt->seskey, pkt->counter);
			send_udp(curconn, &pdata);
			break;

		case MT_PTYPE_END:
			curconn = list_find_connection(pkt->seskey, &pkt->srcaddr);
			if (!curconn)
				break;

			if (curconn->state != STATE_CLOSED) {
				init_packet(&pdata, MT_PTYPE_END, &pkt->dstaddr, &pkt->srcaddr, pkt->seskey, pkt->counter);
				send_udp(curconn, &pdata);
			}
			syslog(LOG_DEBUG, "(%d) Connection closed.", curconn->seskey);
			list_remove_connection(curconn);
			return;

		case MT_PTYPE_ACK:
			curconn = list_find_connection(pkt->seskey, &pkt->srcaddr);
			if (!curconn)
				break;

			if (pkt->counter <= curconn->outcounter) {
				curconn->wait_for_ack = 0;
			}

			if (uloop_timeout_remaining(&curconn->timeout) > 9000) {
				// Answer to anti-timeout packet
				init_packet(&pdata, MT_PTYPE_ACK, &pkt->dstaddr, &pkt->srcaddr, pkt->seskey, pkt->counter);
				send_udp(curconn, &pdata);
			}

			uloop_timeout_set(&curconn->timeout, MT_CONNECTION_TIMEOUT * 1000);
			return;

		case MT_PTYPE_DATA:
			curconn = list_find_connection(pkt->seskey, &pkt->srcaddr);
			if (!curconn)
				break;

			uloop_timeout_set(&curconn->timeout, MT_CONNECTION_TIMEOUT * 1000);

			/* ack the data packet */
			init_packet(&pdata, MT_PTYPE_ACK, &pkt->dstaddr, &pkt->srcaddr, pkt->seskey, pkt->counter + (data_len - MT_HEADER_LEN));
			send_udp(curconn, &pdata);

			/* Accept first packet, and all packets greater than incounter, and if counter has
			wrapped around. */
			if (curconn->incounter == 0 || pkt->counter > curconn->incounter || (curconn->incounter - pkt->counter) > 16777216) {
				curconn->incounter = pkt->counter;
			} else {
				/* Ignore double or old packets */
				return;
			}

			handle_data_packet(curconn, pkt, data_len);
			break;

		default:
			if (curconn) {
				syslog(LOG_WARNING, "(%d) Unhandeled packet type: %d", curconn->seskey, pkt->ptype);
				init_packet(&pdata, MT_PTYPE_ACK, &pkt->dstaddr, &pkt->srcaddr, pkt->seskey, pkt->counter);
				send_udp(curconn, &pdata);
			}
		}
	if (0 && curconn != NULL) {
		printf("Packet, incounter %d, outcounter %d\n", curconn->incounter, curconn->outcounter);
	}
}

static void print_version() {
	fprintf(stderr, PROGRAM_NAME " " PROGRAM_VERSION "\n");
}

void mndp_broadcast(struct uloop_timeout *utm) {
	struct mt_packet pdata;
	struct utsname s_uname;
	uint32_t uptime;
	struct sysinfo s_sysinfo;
	struct net_interface *iface;
	struct mt_mndp_hdr *header;

	if (sysinfo(&s_sysinfo) != 0) {
		return;
	}

	/* Seems like ping uptime is transmitted as little endian? */
	uptime = htole32(s_sysinfo.uptime);

	if (uname(&s_uname) != 0) {
		return;
	}

	list_for_each_entry(iface, &ifaces, list)
	{
		header = (struct mt_mndp_hdr *)&(pdata.data);

		mndp_init_packet(&pdata, 0, 1);
		mndp_add_attribute(&pdata, MT_MNDPTYPE_ADDRESS, &iface->mac_addr, ETH_ALEN);
		mndp_add_attribute(&pdata, MT_MNDPTYPE_IDENTITY, s_uname.nodename, strlen(s_uname.nodename));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_VERSION, s_uname.release, strlen(s_uname.release));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_PLATFORM, PLATFORM_NAME, strlen(PLATFORM_NAME));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_HARDWARE, s_uname.machine, strlen(s_uname.machine));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_TIMESTAMP, &uptime, 4);

#ifdef TELNET_SUPPORT
		if (!tunnel_conn)
			mndp_add_attribute(&pdata, MT_MNDPTYPE_SOFTID, MT_SOFTID_MACTELNET, strlen(MT_SOFTID_MACTELNET));
		else
#endif
			mndp_add_attribute(&pdata, MT_MNDPTYPE_SOFTID, MT_SOFTID_MACSSH, strlen(MT_SOFTID_MACSSH));

		mndp_add_attribute(&pdata, MT_MNDPTYPE_IFNAME, iface->name, strlen(iface->name));
		header->cksum = in_cksum((uint16_t *)&(pdata.data), pdata.size);
		send_special_udp(iface, MT_MNDP_PORT, &pdata);
	}

	if (utm)
		uloop_timeout_set(utm, MT_MNDP_BROADCAST_INTERVAL * 1000);
}

void sigterm_handler() {
	struct mt_connection *p;
	struct mt_packet pdata;
	/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
	char message[] = "\r\n\r\nDaemon shutting down.\r\n";

	syslog(LOG_NOTICE, "Daemon shutting down");

	list_for_each_entry(p, &connections, list) {
		if (p->state == STATE_ACTIVE) {
			init_packet(&pdata, MT_PTYPE_DATA, &p->interface->mac_addr, &p->srcmac, p->seskey, p->outcounter);
			add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, message, strlen(message));
			send_udp(p, &pdata);

			init_packet(&pdata, MT_PTYPE_END, &p->interface->mac_addr, &p->srcmac, p->seskey, p->outcounter);
			send_udp(p, &pdata);
		}
	}

	/* Doesn't hurt to tidy up */
	close(sockfd);
	closelog();
	exit(0);
}

void sighup_handler() {
	struct mt_connection *p, *tmp;
	struct net_interface *iface;

	syslog(LOG_NOTICE, "SIGHUP: Reloading interfaces");

	net_ifaces_init();

	/* Reassign outgoing interfaces to connections again, since they may have changed */
	list_for_each_entry_safe(p, tmp, &connections, list)
	{
		iface = net_ifaces_add(p->interface_name);

		if (!iface)
		{
			syslog(LOG_NOTICE, "(%d) Connection closed because interface %s is gone.", p->seskey, p->interface_name);
			list_remove_connection(p);
			continue;
		}

		p->interface = iface;
	}

	net_ifaces_finish();
}

static void recv_telnet(struct uloop_fd *ufd, uint32_t ev)
{
	struct sockaddr_in src = { };
	struct mt_mactelnet_hdr hdr = { };
	int in_ifindex = 0;

	int len = net_recv_packet(ufd->fd, &hdr, &src, &in_ifindex);

	if (len <= 0)
		return;

	handle_packet(&hdr, &src, len, in_ifindex);
}

static void recv_mndp(struct uloop_fd *ufd, uint32_t ev)
{
	int len = net_recv_packet(ufd->fd, NULL, NULL, NULL);

	if (len != 4)
		return;

	/* max 1 rps */
	if (time(NULL) - last_mndp_time <= 0)
		return;

	mndp_broadcast(NULL);
	time(&last_mndp_time);
}

static void recv_bulk(struct uloop_fd *ufd, uint32_t ev)
{
	struct mt_connection *p = container_of(ufd, struct mt_connection, socket);
	struct mt_packet pdata;
	uint8_t keydata[1024];
	int datalen,plen;

	/* Read it */
	datalen = read(ufd->fd, &keydata, 1024);

	if (datalen > 0) {
		/* Send it */
		init_packet(&pdata, MT_PTYPE_DATA, &p->dstmac, &p->srcmac, p->seskey, p->outcounter);
		plen = add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, &keydata, datalen);
		p->outcounter += plen;
		p->wait_for_ack = 1;
		send_udp(p, &pdata);
	} else {
		/* Shell exited */
		init_packet(&pdata, MT_PTYPE_END, &p->dstmac, &p->srcmac, p->seskey, p->outcounter);
		send_udp(p, &pdata);
		if (tunnel_conn) {
			syslog(LOG_INFO, "(%d) Connection to server closed.", p->seskey);
		}
#ifdef TELNET_SUPPORT
		else if (p->username != NULL) {
			syslog(LOG_INFO, "(%d) Connection to user %s closed.", p->seskey, p->username);
		}
#endif
		else {
			syslog(LOG_INFO, "(%d) Connection closed.", p->seskey);
		}
		list_remove_connection(p);
	}
}

static void timeout_session(struct uloop_timeout *utm)
{
	struct mt_packet pdata;
	struct mt_connection *p = container_of(utm, struct mt_connection, timeout);

	syslog(LOG_INFO, "(%d) Session timed out", p->seskey);
	init_packet(&pdata, MT_PTYPE_DATA, &p->dstmac, &p->srcmac, p->seskey, p->outcounter);
	/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
	add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, "Timeout\r\n", 9);
	send_udp(p, &pdata);
	init_packet(&pdata, MT_PTYPE_END, &p->dstmac, &p->srcmac, p->seskey, p->outcounter);
	send_udp(p, &pdata);

	list_remove_connection(p);
}

/*
 * TODO: Rewrite main() when all sub-functionality is tested
 */
int main (int argc, char **argv) {
	int c;
	int print_help = 0;
	int foreground = 0;
	char port[sizeof("65535\0")];
	uint8_t drop_priv = 0;
	struct net_interface *iface;
	struct uloop_timeout mndpintv = { };
	struct uloop_fd insock = { }, mndpsock = { };

	net_ifaces_init();

	while ((c = getopt(argc, argv, "fnvh?SP:U:i:c:")) != -1) {
		switch (c) {
			case 'f':
				foreground = 1;
				break;

			case 'n':
				break;

			case 'S':
				tunnel_conn = 1;
				break;

			case 'F':
				tunnel_conn = 1;
				break;

			case 'P':
				fwdport = atoi(optarg);
				break;

			case 'U':
				/* Save nonpriv_username */
				strncpy(nonpriv_username, optarg, sizeof(nonpriv_username) - 1);
				nonpriv_username[sizeof(nonpriv_username) - 1] = '\0';
				drop_priv = 1;
				break;

			case 'c':
				/* Save command to execute */
				strncpy(exec_command, optarg, sizeof(exec_command) - 1);
				exec_command[sizeof(exec_command) - 1] = '\0';
				break;

			case 'v':
				print_version();
				exit(0);
				break;

			case 'h':
			case '?':
				print_help = 1;
				break;

			case 'i':
				iface = net_ifaces_add(optarg);
				if (!iface)
					fprintf(stderr, "No such interface: %s\n", optarg);
				else
					syslog(LOG_NOTICE, "Listening on %s for %s\n",
						   iface->name, ether_ntoa(&iface->mac_addr));
				break;
		}
	}

#ifndef TELNET_SUPPORT
	tunnel_conn = 1;
#endif

	/* If no -i specified, listen on all interfaces */
	if (list_empty(&ifaces))
		net_ifaces_add_all();

	net_ifaces_finish();

	if (print_help) {
		print_version();
		fprintf(stderr, "Usage: %s [-v] [-h] [-n] [-f] [-S] [-P <port>] [-U <user>] [-c <command>]\n", argv[0]);
		fprintf(stderr, "\nParameters:\n"
				"  -f         Run process in foreground.\n"
				"  -n         Do not use broadcast packets. Just a tad less insecure.\n"
				"  -S / -F    Forwarding of TCP connections through  MAC-Telnet protocol,\n"
				"             instead of using the standard MAC-Telnet remote terminal.\n"
				"  -P <port>  Local TCP port used for forwarding connections to SSH Server.\n"
				"             (If not specified, port 22 by default.)\n"
				"  -U <user>  Drop privileges by switching to user, when the command is\n"
				"             run as a privileged user in conjunction with the -n option.\n"
				"             Standard MAC-Telnet is not compatible with this option.\n"
				"  -c <cmd>   Execute specified command instead of user's shell after login.\n"
				"             No authentication required when this option is set.\n"
				"             The client will interact directly with the command.\n"
				"  -i <iface> Listen on given interface.\n"
				"  -v         Print version and exit.\n"
				"  -h         Print help and exit.\n"
				"\n");
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "You need to have root privileges to use %s.\n", argv[0]);
		return 1;
	}

	if (list_empty(&ifaces)) {
		fprintf(stderr, "Unable to find any valid network interfaces\n");
		return 1;
	}

	/* Try to read user file */
	if (!tunnel_conn && exec_command[0] == '\0') {
		read_userfile();
	}

	/* Seed randomizer */
	srand(time(NULL));

	sockfd = net_init_raw_socket();

	if (drop_priv) {
		if (tunnel_conn) {
			drop_privileges(nonpriv_username);
		}
		else {
			fprintf(stderr, "Drop privileges (-U) option ignored. "
							"Standard MAC-Telnet is not compatible with this option.\n");
		}
	}

	openlog("mactelnetd", LOG_PID, LOG_DAEMON);

	/* Receive regular udp packets with this socket */
	snprintf(port, sizeof(port), "%d", MT_MACTELNET_PORT);
	insock.cb = recv_telnet;
	insock.fd = usock(USOCK_UDP|USOCK_IPV4ONLY|USOCK_NUMERIC|USOCK_SERVER, "0.0.0.0", port);

	if (insock.fd < 0) {
		fprintf(stderr, "Error binding to 0.0.0.0:%s, %s\n", port, strerror(errno));
		return 1;
	} else {
		syslog(LOG_NOTICE, "Bound to 0.0.0.0:%s", port);
	}

	/* Enable IP_PKTINFO so recvmsg can report which interface each packet
	 * arrived on.  This allows net_ifaces_lookup_ifindex() to distinguish
	 * interfaces that share the same MAC address (e.g. lan1/lan2/lan3). */
	{
		int one = 1;
		if (setsockopt(insock.fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one)) < 0)
			syslog(LOG_WARNING, "setsockopt IP_PKTINFO: %s", strerror(errno));
	}

	/* Receive mndp udp packets with this socket */
	snprintf(port, sizeof(port), "%d", MT_MNDP_PORT);
	mndpsock.cb = recv_mndp;
	mndpsock.fd = usock(USOCK_UDP|USOCK_IPV4ONLY|USOCK_NUMERIC|USOCK_SERVER, "0.0.0.0", port);

	if (mndpsock.fd < 0) {
		fprintf(stderr, "MNDP: Error binding to 0.0.0.0:%s, %s\n", port, strerror(errno));
	}

	if (!foreground)
		daemon(0, 0);

	/* Handle zombies etc */
	signal(SIGCHLD,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGPIPE,SIG_IGN);
	signal(SIGHUP, sighup_handler);
	signal(SIGTERM, sigterm_handler);

	uloop_init();

	uloop_fd_add(&insock, ULOOP_READ);
	uloop_fd_add(&mndpsock, ULOOP_READ);

	mndpintv.cb = mndp_broadcast;
	mndp_broadcast(&mndpintv);

	uloop_run();

	/* Never reached */
	return 0;
}
