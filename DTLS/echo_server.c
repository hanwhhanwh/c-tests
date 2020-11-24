/**
 * Copyright (C) 2020 hbesthee@naver.com
 *
 * All rights reserved.
*/

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include "utils.h"


int verbose = 0;
int veryverbose = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

char Usage[] =
"Usage: echo_server [options]\n"
"Options:\n"
"        -l      message length (Default: 100 Bytes)\n"
"        -p      port (Default: 23232)\n"
"        -v      verbose\n"
"        -V      very verbose\n";



int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
		{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
			{
			printf("error setting random cookie secret\n");
			return 0;
			}
		cookie_initialized = 1;
		}

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
				   &peer.s6.sin6_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s6.sin6_addr,
				   sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
				   &peer.s4.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s4.sin_addr,
				   sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
				   &peer.s6.sin6_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.s6.sin6_addr,
				   sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
	}

struct pass_info {
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} server_addr, client_addr;
	SSL *ssl;
};

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}

#ifdef WIN32
DWORD WINAPI connection_handle(LPVOID *info) {
#else
void* connection_handle(void *info) {
#endif
	ssize_t len;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	struct pass_info *pinfo = (struct pass_info*) info;
	SSL *ssl = pinfo->ssl;
	int fd, reading = 0, ret;
	const int on = 1, off = 0;
	struct timeval timeout;
	int num_timeouts = 0, max_timeouts = 5;

#ifndef WIN32
	pthread_detach(pthread_self());
#endif

	OPENSSL_assert(pinfo->client_addr.ss.ss_family == pinfo->server_addr.ss.ss_family);
	fd = socket(pinfo->client_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		goto cleanup;
	}

#ifdef WIN32
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, (socklen_t) sizeof(on));
#else
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif
#endif
	switch (pinfo->client_addr.ss.ss_family) {
		case AF_INET:
			if (bind(fd, (const struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in))) {
				perror("bind");
				goto cleanup;
			}
			if (connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(struct sockaddr_in))) {
				perror("connect");
				goto cleanup;
			}
			break;
		case AF_INET6:
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
			if (bind(fd, (const struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in6))) {
				perror("bind");
				goto cleanup;
			}
			if (connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(struct sockaddr_in6))) {
				perror("connect");
				goto cleanup;
			}
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr.ss);

	/* Finish handshake */
	do { ret = SSL_accept(ssl); }
	while (ret == 0);
	if (ret < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		goto cleanup;
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	if (verbose) {
		if (pinfo->client_addr.ss.ss_family == AF_INET) {
			printf ("\nThread %lx: accepted connection from %s:%d\n",
					id_function(),
					inet_ntop(AF_INET, &pinfo->client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(pinfo->client_addr.s4.sin_port));
		} else {
			printf ("\nThread %lx: accepted connection from %s:%d\n",
					id_function(),
					inet_ntop(AF_INET6, &pinfo->client_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(pinfo->client_addr.s6.sin6_port));
		}
	}

	if (veryverbose && SSL_get_peer_certificate(ssl)) {
		printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
	}

	while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) && num_timeouts < max_timeouts) {

		reading = 1;
		while (reading) {
			len = SSL_read(ssl, buf, sizeof(buf));

			switch (SSL_get_error(ssl, len)) {
				case SSL_ERROR_NONE:
					if (verbose) {
						printf("Thread %lx: read %d bytes\n", id_function(), (int) len);
					}
					reading = 0;
					break;
				case SSL_ERROR_WANT_READ:
					/* Handle socket timeouts */
					if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
						num_timeouts++;
						reading = 0;
					}
					/* Just try again */
					break;
				case SSL_ERROR_ZERO_RETURN:
					reading = 0;
					break;
				case SSL_ERROR_SYSCALL:
					printf("Socket read error: ");
					if (!handle_socket_error()) goto cleanup;
					reading = 0;
					break;
				case SSL_ERROR_SSL:
					printf("SSL read error: ");
					printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
					goto cleanup;
					break;
				default:
					printf("Unexpected error while reading!\n");
					goto cleanup;
					break;
			}
		}

		if (len > 0) {
			len = SSL_write(ssl, buf, len);

			switch (SSL_get_error(ssl, len)) {
				case SSL_ERROR_NONE:
					if (verbose) {
						printf("Thread %lx: wrote %d bytes\n", id_function(), (int) len);
					}
					break;
				case SSL_ERROR_WANT_WRITE:
					/* Can't write because of a renegotiation, so
					 * we actually have to retry sending this message...
					 */
					break;
				case SSL_ERROR_WANT_READ:
					/* continue with reading */
					break;
				case SSL_ERROR_SYSCALL:
					printf("Socket write error: ");
					if (!handle_socket_error()) goto cleanup;
					//reading = 0;
					break;
				case SSL_ERROR_SSL:
					printf("SSL write error: ");
					printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
					goto cleanup;
					break;
				default:
					printf("Unexpected error while writing!\n");
					goto cleanup;
					break;
			}
		}
	}

	SSL_shutdown(ssl);

cleanup:
#ifdef WIN32
	closesocket(fd);
#else
	close(fd);
#endif
	free(info);
	SSL_free(ssl);
	if (verbose)
		printf("Thread %lx: done, connection closed.\n", id_function());
#if WIN32
	ExitThread(0);
#else
	pthread_exit( (void *) NULL );
#endif
}


void start_server(int port, char *local_address) {
	int fd;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} server_addr, client_addr;
#if WIN32
	WSADATA wsaData;
	DWORD tid;
#else
	pthread_t tid;
#endif
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	struct timeval timeout;
	struct pass_info *info;
	const int on = 1, off = 0;

	memset(&server_addr, 0, sizeof(struct sockaddr_storage));
	if (strlen(local_address) == 0) {
		server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		server_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		server_addr.s6.sin6_addr = in6addr_any;
		server_addr.s6.sin6_port = htons(port);
	} else {
		if (inet_pton(AF_INET, local_address, &server_addr.s4.sin_addr) == 1) {
			server_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			server_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
			server_addr.s4.sin_port = htons(port);
		} else if (inet_pton(AF_INET6, local_address, &server_addr.s6.sin6_addr) == 1) {
			server_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
			server_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
			server_addr.s6.sin6_port = htons(port);
		} else {
			return;
		}
	}

	THREAD_setup();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(DTLS_server_method());
	/* We accept all ciphers, including NULL.
	 * Not recommended beyond testing and debugging
	 */
	//SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

#ifdef WIN32
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

	fd = socket(server_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}

#ifdef WIN32
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, (socklen_t) sizeof(on));
#else
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#if defined(SO_REUSEPORT) && !defined(__linux__)
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif
#endif

	if (server_addr.ss.ss_family == AF_INET) {
		if (bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in))) {
			perror("bind");
			exit(EXIT_FAILURE);
		}
	} else {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&off, sizeof(off));
		if (bind(fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in6))) {
			perror("bind");
			exit(EXIT_FAILURE);
		}
	}
	while (1) {
		memset(&client_addr, 0, sizeof(struct sockaddr_storage));

		/* Create BIO */
		bio = BIO_new_dgram(fd, BIO_NOCLOSE);

		/* Set and activate timeouts */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

		ssl = SSL_new(ctx);

		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

		while (DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr) <= 0);

		info = (struct pass_info*) malloc (sizeof(struct pass_info));
		memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_storage));
		memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_storage));
		info->ssl = ssl;

#ifdef WIN32
		if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) connection_handle, info, 0, &tid) == NULL) {
			exit(-1);
		}
#else
		if (pthread_create( &tid, NULL, connection_handle, info) != 0) {
			perror("pthread_create");
			exit(-1);
		}
#endif
	}

	THREAD_cleanup();
#ifdef WIN32
	WSACleanup();
#endif
}


int main(int argc, char **argv)
{
	int port = 23232;
	int length = 100;
	int messagenumber = 5;
	char local_addr[INET6_ADDRSTRLEN+1];

	memset(local_addr, 0, INET6_ADDRSTRLEN+1);

	argc--;
	argv++;

	while (argc >= 1) {
		if	(strcmp(*argv, "-l") == 0) {
			if (--argc < 1) goto cmd_err;
			length = atoi(*++argv);
			if (length > BUFFER_SIZE)
				length = BUFFER_SIZE;
		}
		else if	(strcmp(*argv, "-L") == 0) {
			if (--argc < 1) goto cmd_err;
			strncpy(local_addr, *++argv, INET6_ADDRSTRLEN);
		}
		else if	(strcmp(*argv, "-n") == 0) {
			if (--argc < 1) goto cmd_err;
			messagenumber = atoi(*++argv);
		}
		else if	(strcmp(*argv, "-p") == 0) {
			if (--argc < 1) goto cmd_err;
			port = atoi(*++argv);
		}
		else if	(strcmp(*argv, "-v") == 0) {
			verbose = 1;
		}
		else if	(strcmp(*argv, "-V") == 0) {
			verbose = 1;
			veryverbose = 1;
		}
		else if	(((*argv)[0]) == '-') {
			goto cmd_err;
		}
		else break;

		argc--;
		argv++;
	}

	if (argc > 1) goto cmd_err;

	if (OpenSSL_version_num() != OPENSSL_VERSION_NUMBER) {
		printf("Warning: OpenSSL version mismatch!\n");
		printf("Compiled against %s\n", OPENSSL_VERSION_TEXT);
		printf("Linked against   %s\n", OpenSSL_version(OPENSSL_VERSION));

		if (OpenSSL_version_num() >> 20 != OPENSSL_VERSION_NUMBER >> 20) {
			printf("Error: Major and minor version numbers must match, exiting.\n");
			exit(EXIT_FAILURE);
		}
	} else if (verbose) {
		printf("Using %s\n", OpenSSL_version(OPENSSL_VERSION));
	}

	if (OPENSSL_VERSION_NUMBER < 0x1010102fL) {
		printf("Error: %s is unsupported, use OpenSSL Version 1.1.1a or higher\n", OpenSSL_version(OPENSSL_VERSION));
		exit(EXIT_FAILURE);
	}

	start_server(port, local_addr);

	return 0;

cmd_err:
	fprintf(stderr, "%s\n", Usage);
	return 1;
}
