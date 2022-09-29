// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

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
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <dirent.h>

#include "version.h"

#define ERR(str, ...) fprintf(stderr, "Error: "str, ##__VA_ARGS__)

struct hexend {
	char iface[IFNAMSIZ];
	uint8_t buffer[ETH_FRAME_LEN];
	bool quiet;
	bool verbose;
	int length;
	int reps;
	float interval;
};


void usage(void)
{
	fputs("hexend - Send raw hex frames\n"
	      "\n"
	      "USAGE:\n"
	      "        hexend <iface> [FILE] [OPTIONS]\n"
	      "\n"
	      "        File may only contain hexadecimal characters and whitespace.\n"
	      "\n"
	      "OPTIONS:\n"
	      "        -c, --count <NUM>\n"
	      "            Repeat NUM times\n"
	      "        -h, --help\n"
	      "            Display this help text\n"
	      "        -i, --interval <NUM>\n"
	      "            Repeat at NUM second(s) interval (supports fractions)\n"
	      "        -v, --verbose\n"
	      "            Display the frame you are sending\n"
	      "        -V, --version\n"
	      "            Display hexend version\n"
	      "        -q, --quiet \n"
	      "            Suppress all output\n"
	      "\n"
	      "EXAMPLES:\n"
	      "            hexend eth0 bcast\n"
	      "            hexend eth0 my_frames/frame.hex\n"
	      "            cat my_frames/frame.hex | hexend eth0\n"
	      "            echo ffffffffffffaaaaaaaaaaaa0000 | hexend eth0\n"
	      "\n"
	      ,stderr);
}

void show_buffer(uint8_t buffer[ETH_FRAME_LEN], int length)
{
	int i = 0;

	while (i < length) {
		printf("%02x", buffer[i]);;
		i++;
		if (i < length) {
			printf("%02x", buffer[i]);;
			i++;
		}

		if (i % 16 == 0)
			printf("\n");
		else
			printf(" ");

	}
	if (i % 16 != 0)
		printf("\n");
}

int parse_hex_file(FILE *input, uint8_t *buffer, int *length, bool quiet)
{
	char byte[3] = {0}; /* Null terminated so we can use strtol */
	char ch;
	int cnt = 0;

	*length = 0;

	while ((ch = getc(input))) {
		if (ch == EOF)
			break;
		if (isspace(ch))
			continue;
		if (!isxdigit(tolower(ch))) {
			ERR("Invalid character '%c' (ascii: %d) in input\n", ch, ch);
			return -EINVAL;
		}
		
		byte[cnt] = ch;
		cnt++;

		if (cnt == 2) {
			buffer[*length] = strtol(byte, NULL, 16);
			(*length)++;
			cnt = 0;
		}
	}
	/* Can't end on half a byte */
	if (cnt == 1) {
		if (!quiet)
			ERR("Can't end on half a byte\n");
		return -EINVAL;
	}

	if (*length < ETH_HLEN) {
		if (!quiet)
			ERR("Input must be longer than 14 bytes\nMust contain Dest, Src, and EtherType\n");
		return -EINVAL;
	}

	return 0;
}

int parse_arg_iface(int argc, char **argv, struct hexend *hx)
{
	/* Parse interface */
	if (optind == argc) {
		ERR("No interface provided\n");
		return -EINVAL;
	}

	if (strlen(argv[optind]) > 15) {
		ERR("Interface name too long\n");
		return -EINVAL;
	}

	strncpy(hx->iface, argv[optind], IFNAMSIZ);
	optind++;
	return 0;
}

int parse_args(int argc, char **argv, struct hexend *hx)
{
	FILE *input;
	int err = 0;
	char ch;

	struct option long_options[] = {
		{ "version",    no_argument, NULL,            'V' },
		{ "verbose",    no_argument, NULL,            'v' },
		{ "help",       no_argument, NULL,            'h' },
		{ "count",      no_argument, NULL,            'c' },
		{ "interval",   no_argument, NULL,            'i' },
		{ "quiet",      no_argument, NULL,            'q' },
		{ NULL,         0,           NULL,             0  }
	};

	hx->reps = 1;
	hx->quiet = false;
	hx->verbose = false;
	hx->interval = 1;
	hx->length = 0;

	while ((ch = getopt_long(argc, argv, "Vhvqc:i:", long_options, NULL)) != -1) {
		switch (ch) {
		case 'V':
			VERSION();
			return 1;
		case 'h':
			usage();
			return 1;
		case 'v':
			if (hx->quiet) {
				ERR("Can't be verbose and quiet\n");
				return -EINVAL;
			}
			hx->verbose = true;
			break;
		case 'q':
			if (hx->verbose) {
				ERR("Can't be verbose and quiet\n");
				return -EINVAL;
			}
			hx->quiet = true;
			break;
		case 'c':
			// TODO: Replace with strol
			hx->reps = atoi(optarg);
			break;
		case 'i':
			 /*Sending interval. Float. */
			hx->interval = atof(optarg);
			break;
		case '?':
			return -EINVAL;
		}
	}

	err = parse_arg_iface(argc, argv, hx);
	if (err)
		return err;

	if (optind < argc) {
		input = fopen(argv[optind], "r");
		if (!input) {
			return -ENOENT;
		}
	} else {
		input = stdin;
	}
	err = parse_hex_file(input, hx->buffer, &hx->length, false);
	if (err)
		ERR("Invalid input\n");

	if (input != stdin)
		fclose(input);

	return 0;
}

/* Get the index of the interface to send on */
int get_iface_index(char iface[IFNAMSIZ], int sockfd)
{
	struct ifreq if_idx;

	memset(&if_idx, 0, sizeof(struct ifreq));
#pragma GCC diagnostic ignored "-Wstringop-truncation"
	strncpy(if_idx.ifr_name, iface, IFNAMSIZ);

	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		ERR("No such device: %s\n", iface);
		return -1;
	}

	return if_idx.ifr_ifindex;
}

int send_frame(struct hexend *hx)
{
	struct sockaddr_ll sock_addr;
	bool dots = false;
	int sockfd, reps;

	reps = hx->reps;

	/* Open RAW socket to send on */
	sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		perror("Error");
		return errno;
	}

	sock_addr.sll_ifindex = get_iface_index(hx->iface, sockfd);
	if (sock_addr.sll_ifindex < 0)
		return -EINVAL;

	if (reps > 1)
		dots = true;

	if (!hx->quiet)
		printf("Sending %d bytes\n", hx->length); 
	if (hx->verbose)
		show_buffer(hx->buffer, hx->length);

	/* Send frames */
	while (reps > 0) {
		sendto(sockfd, hx->buffer, hx->length, 0, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_ll));
		reps--;
		if (dots && !hx->quiet) {
			printf(".");
			fflush(stdout);
		}
		if (reps > 0 && hx->interval > 0)
			usleep(1000000 * hx->interval);
	}
	if (dots && !hx->quiet)
		printf("\n");

	close(sockfd);
	return 0;
}

int main(int argc, char **argv)
{
	struct hexend hx;
	int err = 0;

	if (argc <= 1)
		usage();

	err = parse_args(argc, argv, &hx);
	if (err < 0)
		return -err;
	if (err > 0)
		return 0;

	return send_frame(&hx);
}
