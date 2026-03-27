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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <libubox/list.h>

#include "protocol.h"
#include "interfaces.h"

LIST_HEAD(ifaces);

static struct ifaddrs *ifas;
static uint8_t packetbuf[1500];

uint16_t in_cksum(uint16_t *addr, int len)
{
	int nleft = len;
	int sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(uint8_t *) (&answer) = *(uint8_t *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

uint16_t udp_sum_calc(uint8_t *src_addr,uint8_t *dst_addr, uint8_t *data, uint16_t len) {
	uint16_t prot_udp=17;
	uint16_t padd=0;
	uint16_t word16;
	uint32_t sum = 0;
	int i;

	/* Padding ? */
	padd = (len % 2);
	if (padd) {
		data[len] = 0;
	}

	/* header+data */
	for (i = 0; i < len + padd; i += 2){
		word16 = ((data[i] << 8) & 0xFF00) + (data[i + 1] & 0xFF);
		sum += word16;
	}

	/* source ip */
	for (i = 0; i < IPV4_ALEN; i += 2){
		word16 = ((src_addr[i] << 8) & 0xFF00) + (src_addr[i + 1] & 0xFF);
		sum += word16;
	}

	/* dest ip */
	for (i = 0; i < IPV4_ALEN; i += 2){
		word16 = ((dst_addr[i] << 8) & 0xFF00) + (dst_addr[i + 1] & 0xFF);
		sum += word16;
	}

	sum += prot_udp + len;

	while (sum>>16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	sum = ~sum;

	if (sum == 0)
		sum = 0xFFFF;

	return (uint16_t) sum;
}

int net_init_raw_socket(struct net_interface *interface) {
	int fd;

	/* Transmit raw packets with this socket */
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		perror("raw_socket");
		exit(1);
	}

	return fd;
}

int net_send_udp(const int fd, struct net_interface *interface, const struct ether_addr *sourcemac, const struct ether_addr *destmac, const struct in_addr *sourceip, const int sourceport, const struct in_addr *destip, const int destport, const uint8_t *data, const int datalen) {
	struct sockaddr_ll socket_address;

	/*
	 * Create a buffer for the full ethernet frame
	 * and align header pointers to the correct positions.
	*/
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	struct ethhdr *eh = (struct ethhdr *)buffer;
	struct iphdr *ip = (struct iphdr *)(buffer + 14);
	struct udphdr *udp = (struct udphdr *)(buffer + 14 + 20);
	uint8_t *rest = (uint8_t *)(buffer + 20 + 14 + sizeof(struct udphdr));

	if (((void *)rest - (void*)buffer) + datalen  > ETH_FRAME_LEN) {
		fprintf(stderr, "packet size too large\n");
		free(buffer);
		return 0;
	}

	static uint32_t id = 1;
	int send_result = 0;

	/* Abort if we couldn't allocate enough memory */
	if (buffer == NULL) {
		perror("malloc");
		exit(1);
	}

	/* Init ethernet header */
	memcpy(eh->h_source, sourcemac, ETH_ALEN);
	memcpy(eh->h_dest, destmac, ETH_ALEN);
	eh->h_proto = htons(ETH_P_IP);

	/* Init SendTo struct */
	socket_address.sll_family   = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex  = interface->ifindex;
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;

	memcpy(socket_address.sll_addr, eh->h_source, ETH_ALEN);
	socket_address.sll_addr[6]  = 0x00;/*not used*/
	socket_address.sll_addr[7]  = 0x00;/*not used*/

	/* Init IP Header */
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0x10;
	ip->tot_len = htons(datalen + 8 + 20);
	ip->id = htons(id++);
	ip->frag_off = htons(0x4000);
	ip->ttl = 64;
	ip->protocol = 17; /* UDP */
	ip->check = 0x0000;
	ip->saddr = sourceip->s_addr;
	ip->daddr = destip->s_addr;

	/* Calculate checksum for IP header */
	ip->check = in_cksum((uint16_t *)ip, sizeof(struct iphdr));

	/* Init UDP Header */
	udp->source = htons(sourceport);
	udp->dest = htons(destport);
	udp->len = htons(sizeof(struct udphdr) + datalen);
	udp->check = 0;

	/* Insert actual data */
	memcpy(rest, data, datalen);

	/* Add UDP checksum */
	udp->check = udp_sum_calc((uint8_t *)&(ip->saddr), (uint8_t *)&(ip->daddr), (uint8_t *)udp, sizeof(struct udphdr) + datalen);
	udp->check = htons(udp->check);

	/* Send the packet */
	send_result = sendto(fd, buffer, datalen + 8 + 14 + 20, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	if (send_result == -1)
		perror("sendto");

	free(buffer);

	/* Return amount of _data_ bytes sent */
	if (send_result - 8 - 14 - 20 < 0) {
		return 0;
	}

	return send_result - 8 - 14 - 20;
}

int net_recv_packet(int fd, struct mt_mactelnet_hdr *h, struct sockaddr_in *s, int *ifindex)
{
	int result;
	struct iovec iov = { packetbuf, sizeof(packetbuf) };
	uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct msghdr msg = { };
	struct cmsghdr *cmsg;

	memset(packetbuf, 0, sizeof(packetbuf));

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	if (s) {
		msg.msg_name = s;
		msg.msg_namelen = sizeof(*s);
	}

	result = recvmsg(fd, &msg, 0);

	if (result > 0) {
		if (h)
			parse_packet(packetbuf, h);

		if (ifindex) {
			*ifindex = 0;
			for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
				if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
					struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
					*ifindex = pi->ipi_ifindex;
					break;
				}
			}
		}
	}

	return result;
}

void net_ifaces_init(void)
{
	struct net_interface *iface, *tmp;

	if (!list_empty(&ifaces))
		list_for_each_entry_safe(iface, tmp, &ifaces, list)
		{
			list_del(&iface->list);
			free(iface);
		}

	if (getifaddrs(&ifas))
		ifas = NULL;
}

struct net_interface *
net_ifaces_add(const char *ifname)
{
	struct ifaddrs *ifa;
	struct sockaddr_in *sin;
	struct sockaddr_ll *sll;
	struct net_interface *iface;

	if (!ifas || !ifname)
		return NULL;

	iface = calloc(1, sizeof(*iface));

	if (!iface)
		return NULL;

	for (ifa = ifas; ifa; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr || strcmp(ifa->ifa_name, ifname))
			continue;

		switch (ifa->ifa_addr->sa_family)
		{
		case AF_PACKET:
			sll = (struct sockaddr_ll *)ifa->ifa_addr;
			iface->ifindex = sll->sll_ifindex;
			memcpy(&iface->mac_addr, &sll->sll_addr, sizeof(iface->mac_addr));
			break;

		case AF_INET:
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			iface->ipv4_addr = sin->sin_addr;

			if (ifa->ifa_broadaddr)
			{
				sin = (struct sockaddr_in *)ifa->ifa_broadaddr;
				iface->bcast_addr = sin->sin_addr;
			}
			else if (ifa->ifa_netmask)
			{
				sin = (struct sockaddr_in *)ifa->ifa_netmask;
				iface->bcast_addr.s_addr = iface->ipv4_addr.s_addr |
					~sin->sin_addr.s_addr;
			}
			break;

		case AF_INET6:
			{
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
				struct in6_addr *addr = &sin6->sin6_addr;

				/* Check for link-local address (fe80::/10) */
				if ((addr->s6_addr[0] & 0xfe) == 0xfe && (addr->s6_addr[1] & 0xc0) == 0x80) {
					if (!iface->has_ipv6_local) {
						memcpy(&iface->ipv6_local, addr, sizeof(struct in6_addr));
						iface->has_ipv6_local = 1;
					}
				}
				/* Check for global unicast address (2000::/3) */
				else if ((addr->s6_addr[0] & 0xe0) == 0x20) {
					if (!iface->has_ipv6_global) {
						memcpy(&iface->ipv6_global, addr, sizeof(struct in6_addr));
						iface->has_ipv6_global = 1;
					}
				}
			}
			break;
		}
	}

	if (!iface->ifindex)
	{
		free(iface);
		return NULL;
	}

	strncpy(iface->name, ifname, sizeof(iface->name) - 1);
	list_add_tail(&iface->list, &ifaces);

	return iface;
}

struct net_interface *
net_ifaces_lookup(const struct ether_addr *mac)
{
	struct net_interface *iface;

	list_for_each_entry(iface, &ifaces, list)
		if (!memcmp(&iface->mac_addr, mac, sizeof(iface->mac_addr)))
			return iface;

	return NULL;
}

struct net_interface *
net_ifaces_lookup_by_ifindex(int ifindex)
{
	struct net_interface *iface;

	list_for_each_entry(iface, &ifaces, list)
		if (iface->ifindex == ifindex)
			return iface;

	return NULL;
}

void net_ifaces_finish(void)
{
	if (ifas)
		freeifaddrs(ifas);

	ifas = NULL;
}

void net_ifaces_all(void)
{
	struct ifaddrs *ifa;

	net_ifaces_init();

	for (ifa = ifas; ifa; ifa = ifa->ifa_next)
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET)
			net_ifaces_add(ifa->ifa_name);

	net_ifaces_finish();
}

/*
 * Add all available interfaces to the ifaces list without resetting.
 * Must be called between net_ifaces_init() and net_ifaces_finish().
 */
void net_ifaces_add_all(void)
{
	struct ifaddrs *ifa;

	if (!ifas)
		return;

	for (ifa = ifas; ifa; ifa = ifa->ifa_next)
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET)
			net_ifaces_add(ifa->ifa_name);
}

/*
 * Refresh IP addresses for all interfaces in the list.
 * This should be called periodically to detect IP address changes.
 */
void net_ifaces_refresh(void)
{
	struct ifaddrs *ifa;
	struct net_interface *iface;
	struct sockaddr_in *sin;

	/* Re-read interface addresses */
	if (ifas)
		freeifaddrs(ifas);

	if (getifaddrs(&ifas))
		ifas = NULL;

	if (!ifas)
		return;

	/* Update IP addresses for each interface in our list */
	list_for_each_entry(iface, &ifaces, list)
	{
		/* Clear old IP addresses */
		iface->ipv4_addr.s_addr = 0;
		iface->bcast_addr.s_addr = 0;
		iface->has_ipv6_local = 0;
		iface->has_ipv6_global = 0;

		/* Find and update new addresses */
		for (ifa = ifas; ifa; ifa = ifa->ifa_next)
		{
			if (!ifa->ifa_addr || strcmp(ifa->ifa_name, iface->name))
				continue;

			switch (ifa->ifa_addr->sa_family)
			{
			case AF_INET:
				sin = (struct sockaddr_in *)ifa->ifa_addr;
				iface->ipv4_addr = sin->sin_addr;

				if (ifa->ifa_broadaddr)
				{
					sin = (struct sockaddr_in *)ifa->ifa_broadaddr;
					iface->bcast_addr = sin->sin_addr;
				}
				else if (ifa->ifa_netmask)
				{
					sin = (struct sockaddr_in *)ifa->ifa_netmask;
					iface->bcast_addr.s_addr = iface->ipv4_addr.s_addr |
						~sin->sin_addr.s_addr;
				}
				break;

			case AF_INET6:
				{
					struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
					struct in6_addr *addr = &sin6->sin6_addr;

					/* Check for link-local address (fe80::/10) */
					if ((addr->s6_addr[0] & 0xfe) == 0xfe && (addr->s6_addr[1] & 0xc0) == 0x80) {
						if (!iface->has_ipv6_local) {
							memcpy(&iface->ipv6_local, addr, sizeof(struct in6_addr));
							iface->has_ipv6_local = 1;
						}
					}
					/* Check for global unicast address (2000::/3) */
					else if ((addr->s6_addr[0] & 0xe0) == 0x20) {
						if (!iface->has_ipv6_global) {
							memcpy(&iface->ipv6_global, addr, sizeof(struct in6_addr));
							iface->has_ipv6_global = 1;
						}
					}
				}
				break;
			}
		}
	}
}
