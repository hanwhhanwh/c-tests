/**
 * Copyright (C) 2020 hbesthee@naver.com
 *
 * All rights reserved.
*/

#ifndef __UTILS_H_
#define __UTILS_H_


#ifdef WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#define in_port_t u_short
#define ssize_t int
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#endif


#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16


static void locking_function(int mode, int n, const char *file, int line);

static unsigned long id_function(void);

int THREAD_setup();

int THREAD_cleanup();

int handle_socket_error();


#endif