/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __TCPRTT_H
#define __TCPRTT_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct ipv4_data_t {
	unsigned int pid;
	unsigned int  saddr;
	unsigned int  daddr;
	unsigned short sport;
	unsigned short dport;
	unsigned int srtt_ms;
};


struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;
};

#endif /* __TCPRTT_H */
