/*
    Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
    Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>

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
#ifndef _INTERFACES_H
#define _INTERFACES_H 1

#include <net/if.h>
#include <libubox/list.h>

struct net_interface {
	char name[IFNAMSIZ];
	struct in_addr ipv4_addr;
	struct in_addr bcast_addr;
	struct ether_addr mac_addr;
	int ifindex;

	struct list_head list;
};


extern int net_init_raw_socket();
extern int net_send_udp(const int socket, struct net_interface *interface, const struct ether_addr *sourcemac, const struct ether_addr *destmac, const struct in_addr *sourceip, const int sourceport, const struct in_addr *destip, const int destport, const uint8_t *data, const int datalen);
extern uint16_t in_cksum(uint16_t *addr, int len);

extern struct list_head ifaces;

void net_ifaces_init(void);
struct net_interface *net_ifaces_add(const char *ifname);
struct net_interface *net_ifaces_lookup(const struct ether_addr *mac);
struct net_interface *net_ifaces_lookup_ifindex(const struct ether_addr *mac, int ifindex);
void net_ifaces_finish(void);
void net_ifaces_all(void);
void net_ifaces_add_all(void);

int net_recv_packet(int fd, struct mt_mactelnet_hdr *h, struct sockaddr_in *s, int *in_ifindex);

#endif
