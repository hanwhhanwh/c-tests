/**
 * Copyright (C) 2020 hbesthee@naver.com
 *
 * All rights reserved.
*/

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utils.h"


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
