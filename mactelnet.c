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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <endian.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <limits.h>
#include <pwd.h>
#ifdef __LINUX__
#include <linux/if_ether.h>
#endif
#include <libgen.h>
#include "md5.h"
#include "protocol.h"
#include "console.h"
#include "interfaces.h"
#include "users.h"
#include "config.h"
#include "mactelnet.h"
#include "mndp.h"


#define PROGRAM_NAME "MAC-Telnet"

static int sockfd = 0;
static int insockfd;
static int fwdfd = 0;

static uint32_t outcounter = 0;
static uint32_t incounter = 0;
static int sessionkey = 0;
static int running = 1;

static uint8_t use_raw_socket = 1;
static uint8_t terminal_mode = 0;
static int tunnel_conn = 0;
static int launch_ssh = 0;

static struct ether_addr srcmac;
static struct ether_addr dstmac;

static struct in_addr sourceip;
static struct in_addr destip;
static int sourceport;
static int fwdport = MT_TUNNEL_CLIENT_PORT;

static int connect_timeout = CONNECT_TIMEOUT;
static char run_mndp = 0;
static int mndp_timeout = 0;

static int is_a_tty = 1;
static int quiet_mode = 0;
static int batch_mode = 0;
static int no_auth_mode = 1;  /* default: no-auth (server handles auth via exec_command); -o enables legacy auth */

static int keepalive_counter = 0;

static uint8_t encryptionkey[128];
static char username[255] = { };
static char password[255] = { };
static char nonpriv_username[255];
static int sent_auth = 0;

struct net_interface *active_interface;

/* Protocol data direction */
uint8_t mt_direction_fromserver = 0;

static uint32_t send_socket;

static const char *ssh_commands[2] = {
	"dbclient -y -y -p %{port} -l %{user} 127.0.0.1",
	"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p %{port} -l %{user} 127.0.0.1"
};

static char * find_executable(const char *name)
{
	char c, *p, *sp;
	struct stat s;
	static char path[PATH_MAX];

	if (!(p = sp = getenv("PATH")))
		p = sp = "/bin:/usr/bin:/sbin:/usr/sbin";

	do {
		if (*p != ':' && *p != 0)
			continue;

		c = *p; *p = 0;
		snprintf(path, sizeof(path) - 1, "%s/%s", sp, name);

		if (!stat(path, &s) && S_ISREG(s.st_mode) && (s.st_mode & S_IXUSR))
			return path;

		sp = p + 1;
		*p = c;
	}
	while (*p++);

	return NULL;
}

static int exec_ssh(const char *user, int port, int add_argc, char **add_argv)
{
	int i, c, n;
	const char *cmd;
	struct passwd *pwd;
	char *p, *s = NULL, **argv = NULL, portstr[sizeof("65535\0")];

	if (add_argc < 0)
		add_argc = 0;

	if (!user || !*user)
	{
		if (!(pwd = getpwuid(getuid())))
			return -1;

		user = pwd->pw_name;
	}

	for (i = 0; i < sizeof(ssh_commands) / sizeof(ssh_commands[0]); i++)
	{
		if (!ssh_commands[i])
			continue;

		if (!(s = strdup(ssh_commands[i])))
			goto skip;

		for (c = 0, p = strtok(s, "\t "); p != NULL; p = strtok(NULL, "\t "))
			c++;

		free(s);

		if (!(s = strdup(ssh_commands[i])))
			goto skip;

		if (!(argv = calloc(sizeof(*argv), c + add_argc + 1)))
			goto skip;

		argv[0] = strtok(s, "\t ");

		if (!argv[0] || !(cmd = find_executable(argv[0])))
			goto skip;

		for (n = 1; n < c; n++)
		{
			argv[n] = strtok(NULL, "\t ");

			if (!strcmp(argv[n], "%{user}"))
				argv[n] = (char *)user;
			else if (!strcmp(argv[n], "%{port}"))
				sprintf(argv[n] = portstr, "%u", port);
		}

		for (c = 0; c < add_argc; c++)
			argv[n + c] = add_argv[c];

		return execv(cmd, argv);

skip:
		if (s)
			free(s);

		if (argv)
			free(argv);
	}

	return -1;
}

static int handle_packet(struct mt_mactelnet_hdr *pkt, int data_len);

static void print_version() {
	fprintf(stderr, PROGRAM_NAME " " PROGRAM_VERSION "\n");
}

static int send_udp(struct mt_packet *packet, int retransmit) {
	int sent_bytes;
	struct mt_mactelnet_hdr hdr = { };

	/* Clear keepalive counter */
	keepalive_counter = 0;

	if (!use_raw_socket) {
		/* Init SendTo struct */
		struct sockaddr_in socket_address;
		memset(&socket_address, 0, sizeof(socket_address));
		socket_address.sin_family = AF_INET;
		socket_address.sin_port = htons(MT_MACTELNET_PORT);
		socket_address.sin_addr.s_addr = htonl(INADDR_BROADCAST);

		sent_bytes = sendto(send_socket, packet->data, packet->size, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	} else {
		sent_bytes = net_send_udp(sockfd, active_interface, &srcmac, &dstmac, &sourceip,  sourceport, &destip, MT_MACTELNET_PORT, packet->data, packet->size);
	}

	/*
	 * Retransmit packet if no data is received within
	 * retransmit_intervals milliseconds.
	 */
	if (retransmit) {
		int i;

		for (i = 0; i < MAX_RETRANSMIT_INTERVALS; ++i) {
			fd_set read_fds;
			int reads;
			struct timeval timeout;
			int interval = retransmit_intervals[i] * 1000;

			/* Init select */
			FD_ZERO(&read_fds);
			FD_SET(insockfd, &read_fds);
			timeout.tv_sec = 0;
			timeout.tv_usec = interval;

			/* Wait for data or timeout */
			reads = select(insockfd + 1, &read_fds, NULL, NULL, &timeout);
			if (reads && FD_ISSET(insockfd, &read_fds)) {
				int result = net_recv_packet(insockfd, &hdr, NULL);

				/* Handle incoming packets, waiting for an ack */
				if (result > 0 && handle_packet(&hdr, result) == MT_PTYPE_ACK)
					return sent_bytes;
			}

			/* Retransmit */
			send_udp(packet, 0);
		}

		if (is_a_tty && terminal_mode) {
			reset_term();
		}

		fprintf(stderr, "\nConnection timed out\n");
		exit(1);
	}
	return sent_bytes;
}

static void send_auth(char *username, char *password) {
	struct mt_packet data;
	uint16_t width = 0;
	uint16_t height = 0;
	char *terminal = getenv("TERM");
	char md5data[100];
	uint8_t md5sum[17];
	int plen;
	md5_state_t state;

	/* Concat string of 0 + password + encryptionkey */
	md5data[0] = 0;
	strncpy(md5data + 1, password, 82);
	md5data[83] = '\0';
	memcpy(md5data + 1 + strlen(password), encryptionkey, 16);

	/* Generate md5 sum of md5data with a leading 0 */
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)md5data, strlen(password) + 17);
	md5_finish(&state, (md5_byte_t *)md5sum + 1);
	md5sum[0] = 0;

	/* Send combined packet to server */
	init_packet(&data, MT_PTYPE_DATA, &srcmac, &dstmac, sessionkey, outcounter);
	plen = add_control_packet(&data, MT_CPTYPE_PASSWORD, md5sum, 17);
	plen += add_control_packet(&data, MT_CPTYPE_USERNAME, username, strlen(username));
	plen += add_control_packet(&data, MT_CPTYPE_TERM_TYPE, terminal, strlen(terminal));

	if (is_a_tty && get_terminal_size(&width, &height) != -1) {
		width = htole16(width);
		height = htole16(height);
		plen += add_control_packet(&data, MT_CPTYPE_TERM_WIDTH, &width, 2);
		plen += add_control_packet(&data, MT_CPTYPE_TERM_HEIGHT, &height, 2);
	}

	outcounter += plen;

	/* TODO: handle result */
	send_udp(&data, 1);
	sent_auth = 1;
}

static void sig_winch(int sig) {
	uint16_t width,height;
	struct mt_packet data;
	int plen;

	/* terminal height/width has changed, inform server */
	if (get_terminal_size(&width, &height) != -1) {
		init_packet(&data, MT_PTYPE_DATA, &srcmac, &dstmac, sessionkey, outcounter);
		width = htole16(width);
		height = htole16(height);
		plen = add_control_packet(&data, MT_CPTYPE_TERM_WIDTH, &width, 2);
		plen += add_control_packet(&data, MT_CPTYPE_TERM_HEIGHT, &height, 2);
		outcounter += plen;

		send_udp(&data, 1);
	}

	/* reinstate signal handler */
	signal(SIGWINCH, sig_winch);
}

static int handle_packet(struct mt_mactelnet_hdr *pkt, int data_len) {
	/* We only care about packets with correct sessionkey */
	if (pkt->seskey != sessionkey) {
		return -1;
	}

	/* Handle data packets */
	if (pkt->ptype == MT_PTYPE_DATA) {
		struct mt_packet odata;
		struct mt_mactelnet_control_hdr cpkt;
		int success = 0;

		/* Always transmit ACKNOWLEDGE packets in response to DATA packets */
		init_packet(&odata, MT_PTYPE_ACK, &srcmac, &dstmac, sessionkey, pkt->counter + (data_len - MT_HEADER_LEN));
		send_udp(&odata, 0);

		/* Accept first packet, and all packets greater than incounter, and if counter has
		wrapped around. */
		if (incounter == 0 || pkt->counter > incounter || (incounter - pkt->counter) > 65535) {
			incounter = pkt->counter;
		} else {
			/* Ignore double or old packets */
			return -1;
		}

		/* Parse controlpacket data */
		success = parse_control_packet(pkt->data, data_len - MT_HEADER_LEN, &cpkt);

		while (success) {

			/* If we receive encryptionkey, transmit auth data back */
			if (!tunnel_conn && cpkt.cptype == MT_CPTYPE_ENCRYPTIONKEY) {
				memcpy(encryptionkey, cpkt.data, cpkt.length);
				send_auth(username, password);
			}
			/* Using MAC-SSH server must not send authentication request.
			 * Authentication is handled by tunneled SSH Client and Server.
			 */
			else if (tunnel_conn && cpkt.cptype == MT_CPTYPE_ENCRYPTIONKEY) {
				fprintf(stderr, "Server %s does not seem to use MAC-SSH Protocol. Please Try using MAC-Telnet instead.\n", ether_ntoa(&dstmac));
				exit(1);
			}

			/* If the (remaining) data did not have a control-packet magic byte sequence,
			   the data is raw terminal data to be outputted to the terminal. */
			else if (!tunnel_conn && cpkt.cptype == MT_CPTYPE_PLAINDATA) {
				cpkt.data[cpkt.length] = 0;
				fputs((const char *)cpkt.data, stdout);
			}
			/* If the (remaining) data did not have a control-packet magic byte sequence,
			   the data is raw terminal data to be tunneled to local SSH Client. */
			else if (tunnel_conn && cpkt.cptype == MT_CPTYPE_PLAINDATA) {
				if (send(fwdfd, cpkt.data, cpkt.length, 0) < 0) {
					fprintf(stderr, "Terminal client disconnected.\n");
					/* exit */
					running = 0;
				}
			}

			/* END_AUTH means that the user/password negotiation is done, and after this point
			   terminal data may arrive, so we set up the terminal to raw mode. */
			else if (!tunnel_conn && cpkt.cptype == MT_CPTYPE_END_AUTH) {

				if (!sent_auth && !no_auth_mode) {
					fprintf(stderr, "Server %s does not seem to use MAC-Telnet Protocol. Please Try using MAC-SSH instead.\n", ether_ntoa(&dstmac));
					exit(1);
				}

				/* we have entered "terminal mode" */
				terminal_mode = 1;

				if (is_a_tty) {
					/* stop input buffering at all levels. Give full control of terminal to RouterOS */
					raw_term();

					setvbuf(stdin,  (char*)NULL, _IONBF, 0);

					/* Add resize signal handler */
					signal(SIGWINCH, sig_winch);
				}
			}
			else if (tunnel_conn && cpkt.cptype == MT_CPTYPE_END_AUTH) {

			}

			/* Parse next controlpacket */
			success = parse_control_packet(NULL, 0, &cpkt);
		}
	}
	else if (pkt->ptype == MT_PTYPE_ACK) {
		/* Handled elsewhere */
	}

	/* The server wants to terminate the connection, we have to oblige */
	else if (pkt->ptype == MT_PTYPE_END) {
		struct mt_packet odata;

		/* Acknowledge the disconnection by sending a END packet in return */
		init_packet(&odata, MT_PTYPE_END, &srcmac, &dstmac, pkt->seskey, 0);
		send_udp(&odata, 0);

		if (!quiet_mode) {
			fprintf(stderr, "Connection closed.\n");
		}

		/* exit */
		running = 0;
	} else {
		fprintf(stderr, "Unhandeled packet type: %d received from server %s\n", pkt->ptype, ether_ntoa(&dstmac));
		return -1;
	}

	return pkt->ptype;
}

static int find_interface() {
	fd_set read_fds;
	struct mt_packet data;
	struct sockaddr_in myip;
	int testsocket;
	struct timeval timeout;
	int optval = 1;
	struct net_interface *iface;

	net_ifaces_all();

	list_for_each_entry(iface, &ifaces, list)
	{
		if (!strcmp(iface->name, "lo"))
			continue;

		/* Initialize receiving socket on the device chosen */
		myip.sin_family = AF_INET;
		myip.sin_addr = iface->ipv4_addr;
		myip.sin_port = htons(sourceport);

		/* Initialize socket and bind to udp port */
		if ((testsocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			continue;
		}

		setsockopt(testsocket, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
		setsockopt(testsocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

		if (bind(testsocket, (struct sockaddr *)&myip, sizeof(struct sockaddr_in)) == -1) {
			close(testsocket);
			continue;
		}

		/* Set the global socket handle and source mac address for send_udp() */
		send_socket = testsocket;
		srcmac = iface->mac_addr;
		active_interface = iface;

		/* Send a SESSIONSTART message with the current device */
		init_packet(&data, MT_PTYPE_SESSIONSTART, &srcmac, &dstmac, sessionkey, 0);
		send_udp(&data, 0);

		timeout.tv_sec = connect_timeout;
		timeout.tv_usec = 0;

		FD_ZERO(&read_fds);
		FD_SET(insockfd, &read_fds);
		select(insockfd + 1, &read_fds, NULL, NULL, &timeout);
		if (FD_ISSET(insockfd, &read_fds)) {
			/* We got a response, this is the correct device to use */
			return 1;
		}

		close(testsocket);
	}
	return 0;
}

/*
 * TODO: Rewrite main() when all sub-functionality is tested
 */
int main (int argc, char **argv) {
	int result;
	struct mt_packet data;
	struct mt_mactelnet_hdr hdr = { };
	struct sockaddr_in si_me;
	uint8_t print_help = 0;
	uint8_t drop_priv = 0;
	int c;
	int optval = 1;

    /* Ignore args after -- for MAC-Telnet client. */
	int mactelnet_argc = argc;
	int i;
	for (i=0; i < argc; i++) {
		if (strlen(argv[i]) == 2 && strncmp(argv[i], "--", 2) == 0) {
			mactelnet_argc = i;
			break;
		}
	}

	while (1) {
		c = getopt(mactelnet_argc, argv, "bnqlt:u:p:vh?SFP:c:U:BNo");

		if (c == -1) {
			break;
		}

		switch (c) {

			case 'b':
				use_raw_socket = 0;
				break;

			case 'n':
				/* Deprecated: no-broadcast is now the default. Kept for compatibility. */
				break;

			case 'S':
				tunnel_conn = 1;
				launch_ssh = 1;
				break;

			case 'F':
				tunnel_conn = 1;
				break;

			case 'P':
				fwdport = atoi(optarg);
				break;

			case 'u':
				/* Save username */
				strncpy(username, optarg, sizeof(username) - 1);
				break;

			case 'p':
				/* Save password */
				strncpy(password, optarg, sizeof(password) - 1);
				break;

			case 'U':
				/* Save nonpriv_username */
				strncpy(nonpriv_username, optarg, sizeof(nonpriv_username) - 1);
				nonpriv_username[sizeof(nonpriv_username) - 1] = '\0';
				drop_priv = 1;
				break;

			case 'c':
				ssh_commands[0] = optarg;
				ssh_commands[1] = NULL;
				break;

			case 't':
				connect_timeout = atoi(optarg);
				mndp_timeout = connect_timeout;
				break;

			case 'l':
				run_mndp = 1;
				break;

			case 'v':
				print_version();
				exit(0);
				break;

			case 'q':
				quiet_mode = 1;
				break;

			case 'B':
				batch_mode = 1;
				break;

			case 'N':
				no_auth_mode = 1;
				break;

			case 'o':
				/* Enable legacy username/password authentication mode */
				no_auth_mode = 0;
				break;

			case 'h':
			case '?':
				print_help = 1;
				break;

		}
	}
	if (run_mndp) {
		return mndp(mndp_timeout, batch_mode);
	}
	if (argc - optind < 1 || print_help) {
		print_version();
		fprintf(stderr, "Usage: %s <MAC|identity> [-v] [-h] [-q] [-b] [-l] [-B] [-o] [-S] [-P <port>] "
		                "[-t <timeout>] [-u <user>] [-p <pass>] [-c <path>] [-U <user>] [-N]\n", argv[0]);

		if (print_help) {
			fprintf(stderr, "\nParameters:\n"
			"  MAC            MAC-Address of the RouterOS/mactelnetd device. Use MNDP to \n"
			"                 discover it.\n"
			"  identity       The identity/name of your destination device. Uses MNDP \n"
			"                 protocol to find it.\n"
			"  -l             List/Search for routers nearby (MNDP). You may use -t to set timeout.\n"
			"  -B             Batch mode. Use computer readable output (CSV), for use with -l.\n"
			"  -b             Use broadcast packets instead of raw unicast (requires root if omitted).\n"
			"  -t <timeout>   Amount of seconds to wait for a response on each interface.\n"
			"  -u <user>      Specify username on command line.\n"
			"  -p <password>  Specify password on command line.\n"
			"  -U <user>      Drop privileges to this user. Used in conjunction with -n\n"
			"                 for security.\n"
			"  -N             No authentication mode. Skip username/password prompts (default).\n"
			"                 For use with servers not running in -o mode.\n"
			"  -o             Legacy authentication mode. Send username/password to server.\n"
			"                 Required when connecting to a server running with -o.\n"
			"  -S             Use MAC-SSH instead of MAC-Telnet. (Implies -F)\n"
			"                 Forward SSH connection through MAC-Telnet and launch SSH client.\n"
			"  -F             Forward connection through of MAC-Telnet without launching the \n"
			"                 SSH Client.\n"
			"  -P <port>      Local TCP port for forwarding SSH connection.\n"
			"                 (If not specified, port 2222 by default.)\n"
			"  -c <cmdspec>   Override command used for the SSH connection.\n"
			"                 Use %%{user} and %%{port} to substitute the corresponding values.\n"
			"  -q             Quiet mode.\n"
			"  -v             Print version and exit.\n"
			"  -h             This help.\n"
			"\n"
			"All arguments after '--' will be passed to the ssh client command.\n"
			"\n");
		}
		return 1;
	}

	is_a_tty = isatty(fileno(stdout)) && isatty(fileno(stdin));
	if (!is_a_tty) {
		quiet_mode = 1;
	}

	/* Seed randomizer */
	srand(time(NULL));

	if (use_raw_socket) {
		if (geteuid() != 0) {
			fprintf(stderr, "You need to have root privileges for raw socket mode. Use -b to use broadcast instead.\n");
			return 1;
		}

		sockfd = net_init_raw_socket();
	}

	if (drop_priv) {
		drop_privileges(nonpriv_username);
	}

	/* Receive regular udp packets with this socket */
	insockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (insockfd < 0) {
		perror("insockfd");
		return 1;
	}

	if (!use_raw_socket) {
		if (setsockopt(insockfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval))==-1) {
			perror("SO_BROADCAST");
			return 1;
		}
	}

	/* Need to use, to be able to autodetect which interface to use */
	setsockopt(insockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));

	/* Get mac-address from string, or check for hostname via mndp */
	if (!query_mndp_or_mac(argv[optind], &dstmac, !quiet_mode)) {
		/* No valid mac address found, abort */
		return 1;
	}

	if (!tunnel_conn && !no_auth_mode && !username[0]) {
		if (!quiet_mode) {
			printf("Login: ");
			fflush(stdout);
		}
		scanf("%254s", username);
	}

	if (!tunnel_conn && !no_auth_mode && !password[0]) {
		char *tmp = getpass(quiet_mode ? "" : "Password: ");
		strncpy(password, tmp, sizeof(password) - 1);
		password[sizeof(password) - 1] = '\0';
		/* security */
		memset(tmp, 0, strlen(tmp));
	}

	if (tunnel_conn) {
		/* Setup signal handler for broken tunnels. */
		signal(SIGPIPE,SIG_IGN);

		/* Setup Server socket for receiving connection from local SSH Client. */
		int fwdsrvfd;
		fwdsrvfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fwdsrvfd < 0) {
			perror("fwdsrvfd");
			return 1;
		}
		if(setsockopt(fwdsrvfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) {
			perror("SO_REUSEADDR");
			return 1;
		}

		/* Bind to server socket for receiving terminal client connection. */
		struct sockaddr_in srv_socket;
		memset(&srv_socket, 0, sizeof(srv_socket));
		srv_socket.sin_family = AF_INET;
		srv_socket.sin_port = htons(fwdport);
		srv_socket.sin_addr.s_addr = inet_addr("127.0.0.1");
		if (bind(fwdsrvfd, (struct sockaddr *) &srv_socket, sizeof(srv_socket)) < 0) {
			fprintf(stderr, "Error binding to %s:%d, %s\n", "127.0.0.1", fwdport, strerror(errno));
			return 1;
		}
		if (listen(fwdsrvfd, 1) < 0) {
			fprintf(stderr, "Failed listen on server socket %s:%d, %s\n", "127.0.0.1", fwdport, strerror(errno));
			return 1;
		}

		/* Fork child to execute SSH Client locally and connect to parent
		 * waiting for connection from child if launch_ssh is requested.
		 */
		int pid = 0;
		if (launch_ssh) {
			pid = fork();
		}

		if (!launch_ssh || pid > 0) {
			/* Parent code. Waits for connection to local end of tunnel */

			/* Close stdin and stdout, leave stderr active for error messages.
			 * The terminal will be handled by client connecting to local end of tunnel. */
			close(0);
			close(1);

			/* Wait for remote terminal client connection on server port. */
			fprintf(stderr, "Waiting for tunnel connection on port: %d\n", fwdport);
			struct sockaddr_in cli_socket;
			uint32_t cli_socket_len = sizeof(cli_socket);
			memset(&cli_socket, 0, sizeof(cli_socket));
			if ((fwdfd = accept(fwdsrvfd, (struct sockaddr *) &cli_socket, &cli_socket_len)) < 0) {
				perror("fwdfd");
			}
			if(setsockopt(fwdfd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
				perror("SO_KEEPALIVE");
				return 1;
			}
			fprintf(stderr, "Client connected to tunnel from port: %d\n", ntohs(cli_socket.sin_port));
		}
		else if (launch_ssh && pid == 0) {
			/* Child Code. Executes SSH Client and connects to parent to tunnel
			 * connection through MAC-Telnet protocol. */
			if (use_raw_socket) {
				close(sockfd);
			}
			close(insockfd);
			close(fwdsrvfd);

			/* Give time to parent to initialize listening port. */
			sleep(2);

			/* Execute SSH Client. */
			exec_ssh(username, fwdport,
			         argc - mactelnet_argc - 1, &argv[mactelnet_argc + 1]);

			perror("Execution of terminal client failed.");
			exit(1);
		}
		/* Fork failure. */
		else {
			fprintf(stderr, "Execution of terminal client failed.\n");
			if (use_raw_socket) {
				close(sockfd);
			}
			close(insockfd);
			return 1;
		}
	}

	/* Set random source port */
	sourceport = 1024 + (rand() % 1024);

	/* Set up global info about the connection */
	inet_pton(AF_INET, (char *)"255.255.255.255", &destip);
	memcpy(&sourceip, &(si_me.sin_addr), IPV4_ALEN);

	/* Session key */
	sessionkey = rand() % 65535;

	/* stop output buffering */
	setvbuf(stdout, (char*)NULL, _IONBF, 0);

	if (!quiet_mode) {
		printf("Connecting to %s...", ether_ntoa(&dstmac));
	}

	/* Initialize receiving socket on the device chosen */
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(sourceport);

	/* Bind to udp port */
	if (bind(insockfd, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
		fprintf(stderr, "Error binding to %s:%d, %s\n", inet_ntoa(si_me.sin_addr), sourceport, strerror(errno));
		return 1;
	}

	if (!find_interface() || (result = net_recv_packet(insockfd, &hdr, NULL)) < 1) {
		fprintf(stderr, "Connection failed.\n");
		return 1;
	}
	if (!quiet_mode) {
		printf("done\n");
	}

	/* Handle first received packet */
	handle_packet(&hdr, result);

	init_packet(&data, MT_PTYPE_DATA, &srcmac, &dstmac, sessionkey, 0);
	outcounter +=  add_control_packet(&data, MT_CPTYPE_BEGINAUTH, NULL, 0);

	/* TODO: handle result of send_udp */
	result = send_udp(&data, 1);

	while (running) {
		fd_set read_fds;
		int reads;
		static int terminal_gone = 0;
		struct timeval timeout;

		int maxfd = 0;
		maxfd = insockfd > fwdfd ? insockfd : fwdfd;

		/* Init select */
		FD_ZERO(&read_fds);
		if (!tunnel_conn && !terminal_gone) {
			/* Setup fd to read input from terminal. */
			FD_SET(0, &read_fds);
		}
		else if (tunnel_conn) {
			/* Setup fd to read input from local SSH Client. */
			FD_SET(fwdfd, &read_fds);
		}
		FD_SET(insockfd, &read_fds);

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		/* Wait for data or timeout */
		reads = select(maxfd+1, &read_fds, NULL, NULL, &timeout);
		if (reads > 0) {
			/* Handle data from server */
			if (FD_ISSET(insockfd, &read_fds)) {
				result = net_recv_packet(insockfd, &hdr, NULL);

				if (result > 0)
					handle_packet(&hdr, result);
			}
			uint8_t keydata[512];
			int datalen = 0;
			/* Handle data from keyboard/local terminal */
			if (!tunnel_conn && FD_ISSET(0, &read_fds) && terminal_mode) {
				datalen = read(STDIN_FILENO, &keydata, 512);
			}
			/* Handle data from local SSH client */
			if (tunnel_conn && FD_ISSET(fwdfd, &read_fds)) {
				datalen = read(fwdfd, &keydata, 512);
			}
			if (datalen > 0) {
				/* Data received, transmit to server */
				init_packet(&data, MT_PTYPE_DATA, &srcmac, &dstmac, sessionkey, outcounter);
				add_control_packet(&data, MT_CPTYPE_PLAINDATA, &keydata, datalen);
				outcounter += datalen;
				send_udp(&data, 1);
			}
			else if (datalen < 0) {
				terminal_gone = 1;
			}
		/* Handle select() timeout */
		} else {
			/* handle keepalive counter, transmit keepalive packet every 10 seconds
			   of inactivity  */
			if (keepalive_counter++ == 10) {
				struct mt_packet odata;
				init_packet(&odata, MT_PTYPE_ACK, &srcmac, &dstmac, sessionkey, outcounter);
				send_udp(&odata, 0);
			}
		}
	}

	if (!tunnel_conn && is_a_tty && terminal_mode) {
		/* Reset terminal back to old settings */
		reset_term();
	}

	close(sockfd);
	close(insockfd);
	if (tunnel_conn && fwdfd > 0) {
		close(fwdfd);
	}

	return 0;
}
