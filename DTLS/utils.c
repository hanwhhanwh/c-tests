/**
 * Copyright (C) 2020 hbesthee@naver.com
 *
 * All rights reserved.
*/

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utils.h"


int THREAD_setup() {
	int i;

#ifdef WIN32
	mutex_buf = (HANDLE*) malloc(CRYPTO_num_locks() * sizeof(HANDLE));
#else
	mutex_buf = (pthread_mutex_t*) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
#endif
	if (!mutex_buf)
		return 0;
	for (i = 0; i < CRYPTO_num_locks(); i++)
#ifdef WIN32
		mutex_buf[i] = CreateMutex(NULL, FALSE, NULL);
#else
		pthread_mutex_init(&mutex_buf[i], NULL);
#endif
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);
	return 1;
}

int THREAD_cleanup() {
	int i;

	if (!mutex_buf)
		return 0;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++)
#ifdef WIN32
	CloseHandle(mutex_buf[i]);
#else
	pthread_mutex_destroy(&mutex_buf[i]);
#endif
	free(mutex_buf);
	mutex_buf = NULL;
	return 1;
}


int handle_socket_error() {
	switch (errno) {
		case EINTR:
			/* Interrupted system call.
			 * Just ignore.
			 */
			printf("Interrupted system call!\n");
			return 1;
		case EBADF:
			/* Invalid socket.
			 * Must close connection.
			 */
			printf("Invalid socket!\n");
			return 0;
			break;
#ifdef EHOSTDOWN
		case EHOSTDOWN:
			/* Host is down.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Host is down!\n");
			return 1;
#endif
#ifdef ECONNRESET
		case ECONNRESET:
			/* Connection reset by peer.
			 * Just ignore, might be an attacker
			 * sending fake ICMP messages.
			 */
			printf("Connection reset by peer!\n");
			return 1;
#endif
		case ENOMEM:
			/* Out of memory.
			 * Must close connection.
			 */
			printf("Out of memory!\n");
			return 0;
			break;
		case EACCES:
			/* Permission denied.
			 * Just ignore, we might be blocked
			 * by some firewall policy. Try again
			 * and hope for the best.
			 */
			printf("Permission denied!\n");
			return 1;
			break;
		default:
			/* Something unexpected happened */
			printf("Unexpected error! (errno = %d)\n", errno);
			return 0;
			break;
	}
	return 0;
}
