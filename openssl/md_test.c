/**
 * MD engine test
 * @date : 2021-01-09
 * @author : hbesthee@naver.com
 * 참고: https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestInit.html
https://www.openssl.org/docs/man1.1.1/man3/ENGINE_register_all_ciphers.html

TEST :

# ./md_test md5
Digest is: ce73931d2b3da6e60bf18af27494c6cd
# ./md_test sha256
Digest is: 318b20b83a6730b928c46163a2a1cefee4466132731c95c39613acb547ccb715
 */
#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


int main(int argc, char *argv[])
{
	ENGINE *e;
	const char *engine_id = "MD5";
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	char mess1[] = "Test Message\n";
	char mess2[] = "Hello World\n";
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len, i;
	int ret

	if (argv[1] == NULL) {
		printf("Usage: %s digestname\n", argv[0]);
		exit(1);
	}

	// OpenSSL_add_ssl_algorithms();
	// SSL_load_error_strings();

	// Load all bundled ENGINEs into memory and make them visible
	ENGINE_load_builtin_engines();
	// Register all of them for every algorithm they collectively implement
	ENGINE_register_all_complete();

	e = ENGINE_by_id(engine_id);
	if (!e)
		// the engine isn't available
		return 1;
	if (!ENGINE_init(e)) {
		// the engine couldn't initialise, release 'e'
		ENGINE_free(e);
		return 1;
	}

	ret = ENGINE_set_default_digests(e);
	if (ret == 0)
	{
		printf("ENGINE_set_default_digests() fail!\n");
		exit(1);
	}

	md = EVP_get_digestbyname(argv[1]);
	if (md == NULL) {
		printf("Unknown message digest %s\n", argv[1]);
		exit(1);
	}

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
	EVP_DigestUpdate(mdctx, mess2, strlen(mess2));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);

	printf("Digest is: ");
	for (i = 0; i < md_len; i++)
		printf("%02x", md_value[i]);
	printf("\n");

	exit(0);
}
