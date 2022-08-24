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
/*#include <arpa/inet.h>*/
/*#include <netinet/ip.h>*/
/*#include <netinet/udp.h>*/
/*#include <netinet/ether.h>*/
/*#include <linux/if_packet.h>*/
/*#include <sys/ioctl.h>*/

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

int main(int argc, char **argv)
{
	struct ifreq if_idx;
	struct ifreq if_mac;
	int err = 0;
	int sockfd;

	err = parse_args(argc, argv);


	const char *opt = "eth0";
	const int len = strnlen(opt, IFNAMSIZ);

	if (len == IFNAMSIZ) {
		fprintf(stderr, "Too long iface name");
		return 1;
	}
	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
	}

	setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, opt, len);

	write(sockfd, buffer, length);
	close(sockfd);
}
