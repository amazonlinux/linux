// SPDX-License-Identifier: GPL-2.0-only
/*
 * vsock_perf - benchmark utility for vsock.
 *
 * Copyright (C) 2022 SberDevices.
 *
 * Author: Arseniy Krasnov <AVKrasnov@sberdevices.ru>
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <sys/mman.h>

#include "msg_zerocopy_common.h"

#define DEFAULT_BUF_SIZE_BYTES	(128 * 1024)
#define DEFAULT_TO_SEND_BYTES	(64 * 1024)
#define DEFAULT_VSOCK_BUF_BYTES (256 * 1024)
#define DEFAULT_RCVLOWAT_BYTES	1
#define DEFAULT_PORT		1234
#define DEFAULT_LAT_COUNT	10000
#define DEFAULT_LAT_WARMUP	1000

#define BYTES_PER_GB		(1024 * 1024 * 1024ULL)
#define NSEC_PER_SEC		(1000000000ULL)

static unsigned int port = DEFAULT_PORT;
static unsigned long buf_size_bytes = DEFAULT_BUF_SIZE_BYTES;
static unsigned long long vsock_buf_bytes = DEFAULT_VSOCK_BUF_BYTES;
static bool zerocopy;

static void error(const char *s)
{
	perror(s);
	exit(EXIT_FAILURE);
}

static time_t current_nsec(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		error("clock_gettime");

	return (ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;
}

/* From lib/cmdline.c. */
static unsigned long memparse(const char *ptr)
{
	char *endptr;

	unsigned long long ret = strtoull(ptr, &endptr, 0);

	switch (*endptr) {
	case 'E':
	case 'e':
		ret <<= 10;
	case 'P':
	case 'p':
		ret <<= 10;
	case 'T':
	case 't':
		ret <<= 10;
	case 'G':
	case 'g':
		ret <<= 10;
	case 'M':
	case 'm':
		ret <<= 10;
	case 'K':
	case 'k':
		ret <<= 10;
		endptr++;
	default:
		break;
	}

	return ret;
}

static void vsock_increase_buf_size(int fd)
{
	if (setsockopt(fd, AF_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE,
		       &vsock_buf_bytes, sizeof(vsock_buf_bytes)))
		error("setsockopt(SO_VM_SOCKETS_BUFFER_MAX_SIZE)");

	if (setsockopt(fd, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
		       &vsock_buf_bytes, sizeof(vsock_buf_bytes)))
		error("setsockopt(SO_VM_SOCKETS_BUFFER_SIZE)");
}

static int vsock_connect(unsigned int cid, unsigned int port)
{
	union {
		struct sockaddr sa;
		struct sockaddr_vm svm;
	} addr = {
		.svm = {
			.svm_family = AF_VSOCK,
			.svm_port = port,
			.svm_cid = cid,
		},
	};
	int fd;

	fd = socket(AF_VSOCK, SOCK_STREAM, 0);

	if (fd < 0) {
		perror("socket");
		return -1;
	}

	if (connect(fd, &addr.sa, sizeof(addr.svm)) < 0) {
		perror("connect");
		close(fd);
		return -1;
	}

	return fd;
}

static float get_gbps(unsigned long bits, time_t ns_delta)
{
	return ((float)bits / 1000000000ULL) /
	       ((float)ns_delta / NSEC_PER_SEC);
}

static void run_receiver(int rcvlowat_bytes)
{
	unsigned int read_cnt;
	time_t rx_begin_ns;
	time_t in_read_ns;
	size_t total_recv;
	int client_fd;
	char *data;
	int fd;
	union {
		struct sockaddr sa;
		struct sockaddr_vm svm;
	} addr = {
		.svm = {
			.svm_family = AF_VSOCK,
			.svm_port = port,
			.svm_cid = VMADDR_CID_ANY,
		},
	};
	union {
		struct sockaddr sa;
		struct sockaddr_vm svm;
	} clientaddr;

	socklen_t clientaddr_len = sizeof(clientaddr.svm);

	printf("Run as receiver\n");
	printf("Listen port %u\n", port);
	printf("RX buffer %lu bytes\n", buf_size_bytes);
	printf("vsock buffer %llu bytes\n", vsock_buf_bytes);
	printf("SO_RCVLOWAT %d bytes\n", rcvlowat_bytes);

	fd = socket(AF_VSOCK, SOCK_STREAM, 0);

	if (fd < 0)
		error("socket");

	if (bind(fd, &addr.sa, sizeof(addr.svm)) < 0)
		error("bind");

	if (listen(fd, 1) < 0)
		error("listen");

	client_fd = accept(fd, &clientaddr.sa, &clientaddr_len);

	if (client_fd < 0)
		error("accept");

	vsock_increase_buf_size(client_fd);

	if (setsockopt(client_fd, SOL_SOCKET, SO_RCVLOWAT,
		       &rcvlowat_bytes,
		       sizeof(rcvlowat_bytes)))
		error("setsockopt(SO_RCVLOWAT)");

	data = malloc(buf_size_bytes);

	if (!data) {
		fprintf(stderr, "'malloc()' failed\n");
		exit(EXIT_FAILURE);
	}

	read_cnt = 0;
	in_read_ns = 0;
	total_recv = 0;
	rx_begin_ns = current_nsec();

	while (1) {
		struct pollfd fds = { 0 };

		fds.fd = client_fd;
		fds.events = POLLIN | POLLERR |
			     POLLHUP | POLLRDHUP;

		if (poll(&fds, 1, -1) < 0)
			error("poll");

		if (fds.revents & POLLERR) {
			fprintf(stderr, "'poll()' error\n");
			exit(EXIT_FAILURE);
		}

		if (fds.revents & POLLIN) {
			ssize_t bytes_read;
			time_t t;

			t = current_nsec();
			bytes_read = read(fds.fd, data, buf_size_bytes);
			in_read_ns += (current_nsec() - t);
			read_cnt++;

			if (!bytes_read)
				break;

			if (bytes_read < 0) {
				perror("read");
				exit(EXIT_FAILURE);
			}

			total_recv += bytes_read;
		}

		if (fds.revents & (POLLHUP | POLLRDHUP))
			break;
	}

	printf("total bytes received: %zu\n", total_recv);
	printf("rx performance: %f Gbits/s\n",
	       get_gbps(total_recv * 8, current_nsec() - rx_begin_ns));
	printf("total time in 'read()': %f sec\n", (float)in_read_ns / NSEC_PER_SEC);
	printf("average time in 'read()': %f ns\n", (float)in_read_ns / read_cnt);
	printf("POLLIN wakeups: %i\n", read_cnt);

	free(data);
	close(client_fd);
	close(fd);
}

static void enable_so_zerocopy(int fd)
{
	int val = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &val, sizeof(val))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
}

static void run_sender(int peer_cid, unsigned long to_send_bytes)
{
	time_t tx_begin_ns;
	time_t tx_total_ns;
	size_t total_send;
	time_t time_in_send;
	void *data;
	int fd;

	if (zerocopy)
		printf("Run as sender MSG_ZEROCOPY\n");
	else
		printf("Run as sender\n");

	printf("Connect to %i:%u\n", peer_cid, port);
	printf("Send %lu bytes\n", to_send_bytes);
	printf("TX buffer %lu bytes\n", buf_size_bytes);

	fd = vsock_connect(peer_cid, port);

	if (fd < 0)
		exit(EXIT_FAILURE);

	if (zerocopy) {
		enable_so_zerocopy(fd);

		data = mmap(NULL, buf_size_bytes, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (data == MAP_FAILED) {
			perror("mmap");
			exit(EXIT_FAILURE);
		}
	} else {
		data = malloc(buf_size_bytes);

		if (!data) {
			fprintf(stderr, "'malloc()' failed\n");
			exit(EXIT_FAILURE);
		}
	}

	memset(data, 0, buf_size_bytes);
	total_send = 0;
	time_in_send = 0;
	tx_begin_ns = current_nsec();

	while (total_send < to_send_bytes) {
		ssize_t sent;
		size_t rest_bytes;
		time_t before;

		rest_bytes = to_send_bytes - total_send;

		before = current_nsec();
		sent = send(fd, data, (rest_bytes > buf_size_bytes) ?
			    buf_size_bytes : rest_bytes,
			    zerocopy ? MSG_ZEROCOPY : 0);
		time_in_send += (current_nsec() - before);

		if (sent <= 0)
			error("write");

		total_send += sent;

		if (zerocopy) {
			struct pollfd fds = { 0 };

			fds.fd = fd;

			if (poll(&fds, 1, -1) < 0) {
				perror("poll");
				exit(EXIT_FAILURE);
			}

			if (!(fds.revents & POLLERR)) {
				fprintf(stderr, "POLLERR expected\n");
				exit(EXIT_FAILURE);
			}

			vsock_recv_completion(fd, NULL);
		}
	}

	tx_total_ns = current_nsec() - tx_begin_ns;

	printf("total bytes sent: %zu\n", total_send);
	printf("tx performance: %f Gbits/s\n",
	       get_gbps(total_send * 8, time_in_send));
	printf("total time in tx loop: %f sec\n",
	       (float)tx_total_ns / NSEC_PER_SEC);
	printf("time in 'send()': %f sec\n",
	       (float)time_in_send / NSEC_PER_SEC);

	close(fd);

	if (zerocopy)
		munmap(data, buf_size_bytes);
	else
		free(data);
}

static void run_latency_server(void)
{
	union {
		struct sockaddr sa;
		struct sockaddr_vm svm;
	} addr = {
		.svm = {
			.svm_family = AF_VSOCK,
			.svm_port = port,
			.svm_cid = VMADDR_CID_ANY,
		},
	};
	char buf[64];
	int fd;

	printf("Latency server on port %u (echo mode)\n", port);

	fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0)
		error("socket");
	if (bind(fd, &addr.sa, sizeof(addr.svm)) < 0)
		error("bind");
	if (listen(fd, 1) < 0)
		error("listen");

	while (1) {
		int client_fd = accept(fd, NULL, NULL);

		if (client_fd < 0)
			error("accept");

		while (1) {
			ssize_t n = read(client_fd, buf, sizeof(buf));

			if (n <= 0)
				break;
			if (write(client_fd, buf, n) != n)
				break;
		}

		close(client_fd);
	}

	close(fd);
}

static void run_latency_client(int peer_cid, unsigned long count)
{
	unsigned long warmup = DEFAULT_LAT_WARMUP;
	char buf[1] = { 0x42 };
	unsigned long long start, end, rtt;
	unsigned long long rtt_min = 60ULL * NSEC_PER_SEC;
	unsigned long long rtt_max = 0;
	double total_us;
	int fd;

	if (peer_cid < 0) {
		fprintf(stderr, "--latency client requires --sender <cid>\n");
		exit(EXIT_FAILURE);
	}

	printf("Latency client: %lu iterations (+ %lu warmup) to %d:%u\n",
	       count, warmup, peer_cid, port);

	fd = vsock_connect(peer_cid, port);
	if (fd < 0)
		exit(EXIT_FAILURE);

	for (unsigned long i = 0; i < warmup; i++) {
		if (write(fd, buf, 1) != 1)
			error("write (warmup)");
		if (read(fd, buf, 1) != 1)
			error("read (warmup)");
	}

	start = current_nsec();

	for (unsigned long i = 0; i < count; i++) {
		unsigned long long t0 = current_nsec();

		if (write(fd, buf, 1) != 1)
			error("write");
		if (read(fd, buf, 1) != 1)
			error("read");

		rtt = current_nsec() - t0;
		if (rtt < rtt_min)
			rtt_min = rtt;
		if (rtt > rtt_max)
			rtt_max = rtt;
	}

	end = current_nsec();
	total_us = (double)(end - start) / 1000.0;

	printf("RTT min/avg/max: %.1f / %.1f / %.1f us\n",
	       (double)rtt_min / 1000.0,
	       total_us / count,
	       (double)rtt_max / 1000.0);
	printf("  %lu iterations in %.1f ms\n",
	       count, total_us / 1000.0);

	close(fd);
}

static const char optstring[] = "";
static const struct option longopts[] = {
	{
		.name = "help",
		.has_arg = no_argument,
		.val = 'H',
	},
	{
		.name = "sender",
		.has_arg = required_argument,
		.val = 'S',
	},
	{
		.name = "port",
		.has_arg = required_argument,
		.val = 'P',
	},
	{
		.name = "bytes",
		.has_arg = required_argument,
		.val = 'M',
	},
	{
		.name = "buf-size",
		.has_arg = required_argument,
		.val = 'B',
	},
	{
		.name = "vsk-size",
		.has_arg = required_argument,
		.val = 'V',
	},
	{
		.name = "rcvlowat",
		.has_arg = required_argument,
		.val = 'R',
	},
	{
		.name = "zerocopy",
		.has_arg = no_argument,
		.val = 'Z',
	},
	{
		.name = "latency",
		.has_arg = optional_argument,
		.val = 'L',
	},
	{},
};

static void usage(void)
{
	printf("Usage: ./vsock_perf [--help] [options]\n"
	       "\n"
	       "This is benchmarking utility, to test vsock performance.\n"
	       "It runs in two modes: sender or receiver. In sender mode, it\n"
	       "connects to the specified CID and starts data transmission.\n"
	       "\n"
	       "Options:\n"
	       "  --help			This message\n"
	       "  --sender   <cid>		Sender mode (receiver default)\n"
	       "                                <cid> of the receiver to connect to\n"
	       "  --zerocopy			Enable zerocopy (for sender mode only)\n"
	       "  --port     <port>		Port (default %d)\n"
	       "  --bytes    <bytes>KMG		Bytes to send (default %d)\n"
	       "  --buf-size <bytes>KMG		Data buffer size (default %d). In sender mode\n"
	       "                                it is the buffer size, passed to 'write()'. In\n"
	       "                                receiver mode it is the buffer size passed to 'read()'.\n"
	       "  --vsk-size <bytes>KMG		Socket buffer size (default %d)\n"
	       "  --rcvlowat <bytes>KMG		SO_RCVLOWAT value (default %d)\n"
	       "  --latency[=count]		Ping-pong latency mode (default %d iterations)\n"
	       "                                In receiver mode, echo data back.\n"
	       "                                In sender mode, measure round-trip time.\n"
	       "\n", DEFAULT_PORT, DEFAULT_TO_SEND_BYTES,
	       DEFAULT_BUF_SIZE_BYTES, DEFAULT_VSOCK_BUF_BYTES,
	       DEFAULT_RCVLOWAT_BYTES, DEFAULT_LAT_COUNT);
	exit(EXIT_FAILURE);
}

static long strtolx(const char *arg)
{
	long value;
	char *end;

	value = strtol(arg, &end, 10);

	if (end != arg + strlen(arg))
		usage();

	return value;
}

int main(int argc, char **argv)
{
	unsigned long to_send_bytes = DEFAULT_TO_SEND_BYTES;
	unsigned long latency_count = DEFAULT_LAT_COUNT;
	int rcvlowat_bytes = DEFAULT_RCVLOWAT_BYTES;
	int peer_cid = -1;
	bool sender = false;
	bool latency = false;

	while (1) {
		int opt = getopt_long(argc, argv, optstring, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'V': /* Peer buffer size. */
			vsock_buf_bytes = memparse(optarg);
			break;
		case 'R': /* SO_RCVLOWAT value. */
			rcvlowat_bytes = memparse(optarg);
			break;
		case 'P': /* Port to connect to. */
			port = strtolx(optarg);
			break;
		case 'M': /* Bytes to send. */
			to_send_bytes = memparse(optarg);
			break;
		case 'B': /* Size of rx/tx buffer. */
			buf_size_bytes = memparse(optarg);
			break;
		case 'S': /* Sender mode. CID to connect to. */
			peer_cid = strtolx(optarg);
			sender = true;
			break;
		case 'H': /* Help. */
			usage();
			break;
		case 'Z': /* Zerocopy. */
			zerocopy = true;
			break;
		case 'L': /* Latency mode. */
			latency = true;
			if (optarg)
				latency_count = strtolx(optarg);
			break;
		default:
			usage();
		}
	}

	if (latency) {
		if (sender)
			run_latency_client(peer_cid, latency_count);
		else
			run_latency_server();
	} else if (sender) {
		run_sender(peer_cid, to_send_bytes);
	} else {
		run_receiver(rcvlowat_bytes);
	}

	return 0;
}
