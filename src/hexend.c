// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
/*#include <netinet/in.h>*/
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
/*#include <netinet/ip.h>*/
/*#include <netinet/udp.h>*/
/*#include <netinet/ether.h>*/
#include <linux/if_packet.h>
#include <sys/ioctl.h>

#include "version.h"

void usage(void)
{
	fputs("hexend - Send raw hex packets\n"
	      "\n"
	      "USAGE:\n"
	      "        hexend <iface> [hexfile] [OPTIONS]\n"
	      "\n"
	      "OPTIONS:\n"
	      "        -s, --string [HEX]\n"
	      "            Send HEX string instead of reading from file\n"
	      "\n"
	      "EXAMPLES:\n"
	      "            hexend eth0 frame.hex\n"
	      "            hexend eth0 -s \"\\0xFF\\0xFF\\0xFF\\0xFF\\0xFF\\0xFF\"\n"
	      "            cat frame.hex | hexend eth0\n"
	      "\n"
	      ,stderr);
}

int parse_args(int argc, char **argv)
{
	char ch;

	struct option long_options[] = {
		{"version",     no_argument, NULL,            'v' },
		{ "help",       no_argument, NULL,            'h' },
		{NULL,          0,           NULL,            0   }
	};

	while ((ch = getopt_long(argc, argv, "vh", long_options, NULL)) != -1) {

		switch (ch) {
		case 'v':
			VERSION();
			goto out;
		case 'h':
			usage();
			goto out;
		case '?':
			goto out;
		}
	}

	for (; optind <= argc - 1; optind++) { /* Unmatched arguments*/
		printf("Arg: %s\n", argv[optind]);
	}

out:
	/*return err;*/
	return 0;
}

/* Get the index of the interface to send on */
int get_interface_index(const char interface_name[IFNAMSIZ], int sockfd)
{
        struct ifreq if_idx;
        memset(&if_idx, 0, sizeof(struct ifreq));
        strncpy(if_idx.ifr_name, interface_name, IFNAMSIZ-1);
        if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
                perror("SIOCGIFINDEX");

        return if_idx.ifr_ifindex;
}

int send_frame(char *iface, char *buffer, int length)
{

}

int main(int argc, char **argv)
{
	/*struct ifreq if_idx;*/
	/*struct ifreq if_mac;*/
	struct sockaddr_ll sock_addr;
	int err = 0;
	int sockfd;
	/*unsigned char buffer[] = {*/
		/*0xff, 0xff, 0xff, 0xff, 0xff, 0xff,*/
		/*0x00, 0x00, 0x00, 0x00, 0x00, 0x01,*/
		/*0x08, 0x00, 0x00, 0x00, 0x00};*/
	unsigned char buffer[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00};
	int len = 14;
	int bytes = 0;


	/*err = parse_args(argc, argv);*/


	const char opt[IFNAMSIZ] = "veth1";
	const int length = strnlen(opt, IFNAMSIZ);

	if (length == IFNAMSIZ) {
		fprintf(stderr, "Too long iface name");
		return 1;
	}
	/* Open RAW socket to send on */
	sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	/*sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));*/
	perror("socket");


	sock_addr.sll_ifindex = get_interface_index(opt, sockfd);
	/* Address length*/
	/*sock_addr.sll_halen = ETH_ALEN;*/
	/* Destination MAC */
	/*memcpy(sock_addr.sll_addr, buffer, ETH_ALEN);*/

	/*sock_addr.sll_protocol = 0x0800; */

	/* Send packet */
	bytes = sendto(sockfd, buffer, len, 0, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_ll));
	if (bytes < 0)
		printf("Send failed\n");
	else
		printf("Sent %d bytes\n", bytes);

	close(sockfd);

}
