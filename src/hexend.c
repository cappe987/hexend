// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>
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
	      "        -c, --count <NUM>\n"
	      "            Repeat NUM times\n"
	      "        -h, --help\n"
	      "            Display this help text\n"
	      "        -i, --interval <NUM>\n"
	      "            Repeat at NUM second(s) interval (supports fractions)\n"
	      "        -v, --version\n"
	      "            Display hexend version\n"
	      "        -q, --quiet \n"
	      "            Supress all output\n"
	      "\n"
	      "EXAMPLES:\n"
	      "            hexend eth0 frame.hex\n"
	      "            cat frame.hex | hexend eth0\n"
	      "            echo ffffffffffffaaaaaaaaaaaa0000 | hexend eth0\n"
	      "\n"
	      ,stderr);
}

/* Return length? */
int parse_hexbuffer(FILE *input, uint8_t *buffer)
{
	char tmp[3] = {0}; /* Null terminated so we can use strtol */
	char ch;
	int cnt = 0, length = 0;

	while ((ch = getc(input))) {
		if (ch == EOF)
			break;
		if (!isxdigit(tolower(ch)))
			continue;
		
		tmp[cnt] = ch;
		cnt++;

		if (cnt == 2) {
			buffer[length] = strtol(tmp, NULL, 16);
			length++;
			cnt = 0;
		}
	}
	/* Can't end on half a byte */
	if (cnt == 1)
		return -EINVAL;

	return length;
}

int parse_args(int argc, char **argv, char iface[IFNAMSIZ], uint8_t buffer[ETH_FRAME_LEN], int *length, int *reps)
{
	FILE *input = NULL;
	int err = 0;
	char ch;

	struct option long_options[] = {
		{ "version",    no_argument, NULL,            'v' },
		{ "help",       no_argument, NULL,            'h' },
		{ "count",      no_argument, NULL,            'c' },
		{ "interval",   no_argument, NULL,            'i' },
		{ "quiet",      no_argument, NULL,            'q' },
		{ NULL,         0,           NULL,             0  }
	};

	*reps = 1;

	while ((ch = getopt_long(argc, argv, "vhc:f:", long_options, NULL)) != -1) {
		switch (ch) {
		case 'v':
			VERSION();
			goto out;
		case 'h':
			usage();
			goto out;
		case 'c':
			// TODO: Replace with strol
			*reps = atoi(optarg);
			break;
		case 'q':
			 /*Quiet/silent mode */
			fprintf(stderr, "Option -q currently not supported\n");
			break;
		case 'i':
			 /*Sending interval. Float. */
			fprintf(stderr, "Option -i currently not supported\n");
			break;
		case '?':
			goto out;
		}
	}

	/* Parse interface */
	if (optind == argc) {
		fprintf(stderr, "No interface provided\n");
		err = -EINVAL;
		goto out;
	}

	if (strlen(argv[optind]) > 15) {
		fprintf(stderr, "Interface name too long\n");
		err = -EINVAL;
		goto out;
	}
	strncpy(iface, argv[optind], IFNAMSIZ);
	optind++;

	/* Parse filename */
	if (optind == argc) {
		input = stdin;

	} else {
		input = fopen(argv[optind], "r");
	}
	optind++;

	if (!input) {
		fprintf(stderr, "Invalid input file\n");
		err = -EINVAL;
		goto out;
	}

	/* Parse hex string */
	*length = parse_hexbuffer(input, buffer);
	if (*length < 0) {
		err = *length;
		goto out;
	}
	if (*length < 14) {
		fprintf(stderr, "Input must be longer than 14 bytes\nMust contain Dest, Src, and EtherType\n");
		err = -EINVAL;
		goto out;
	}

out:
	if (input && input != stdin) {
		fclose(input);
	}
	return err;
}

/* Get the index of the interface to send on */
int get_iface_index(char iface[IFNAMSIZ], int sockfd)
{
        struct ifreq if_idx;

        memset(&if_idx, 0, sizeof(struct ifreq));
        strncpy(if_idx.ifr_name, iface, IFNAMSIZ - 1);

        if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		fprintf(stderr, "No such device: %s\n", iface);
		return -1;
	}

        return if_idx.ifr_ifindex;
}

int send_frame(char iface[IFNAMSIZ], uint8_t buffer[ETH_FRAME_LEN], int length, int reps)
{
	struct sockaddr_ll sock_addr;
	bool dots = false;
	int sockfd;

	/* Open RAW socket to send on */
	sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
		return errno;

	sock_addr.sll_ifindex = get_iface_index(iface, sockfd);
	if (sock_addr.sll_ifindex < 0)
		return -EINVAL;

	if (reps > 1)
		dots = true;

	printf("Sending %d bytes\n", length); 
	/* Send packet */
	while (reps > 0) {
		sendto(sockfd, buffer, length, 0, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_ll));
		reps--;
		if (dots) {
			printf(".");
			fflush(stdout);
		}
		if (reps > 0)
			usleep(1000000);
	}
	if (dots)
		printf("\n");

	close(sockfd);
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t buffer[ETH_FRAME_LEN];
	char iface[IFNAMSIZ];
	int length, reps, err = 0;

	err = parse_args(argc, argv, iface, buffer, &length, &reps);

	if (err)
		return err;

	return send_frame(iface, buffer, length, reps);
}
