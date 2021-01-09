/**
 * MD engine test
 * @date : 2021-01-09
 * @author : hbesthee@naver.com
 * 참고: https://blog.naver.com/websearch/222143993215

TEST

# ./md_test md5
Digest is: ce73931d2b3da6e60bf18af27494c6cd
# ./md_test sha256
Digest is: 318b20b83a6730b928c46163a2a1cefee4466132731c95c39613acb547ccb715
 */
#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>


int main(int argc, char *argv[])
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	char mess1[] = "Test Message\n";
	char mess2[] = "Hello World\n";
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len, i;

	// Load all bundled ENGINEs into memory and make them visible
	ENGINE_load_builtin_engines();
	// Register all of them for every algorithm they collectively implement
	ENGINE_register_all_complete();

	if (argv[1] == NULL) {
		printf("Usage: %s digestname\n", argv[0]);
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
