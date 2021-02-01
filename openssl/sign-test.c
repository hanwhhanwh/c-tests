/**
 * ECDSA sign test
 * @date : 2021-02-02
 * @author : hbesthee@naver.com
 * 참고: https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestInit.html

TEST :

# ./sign-test
 */
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


int main(int argc, char *argv[])
{
	int        ret;
	ECDSA_SIG *sig;
	EC_KEY    *eckey;
	unsigned char digest[512];
	int dgstlen;

	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL)
	{
		/* error */
		printf("error %d", __LINE__);
	}
	if (EC_KEY_generate_key(eckey) == 0)
	{
		/* error */
		printf("error %d", __LINE__);
	}

	sig = ECDSA_do_sign(digest, 32, eckey);
	if (sig == NULL)
	{
		/* error */
		printf("error %d", __LINE__);
	}

	unsigned char *buffer, *pp;
	int buf_len;

	buf_len = ECDSA_size(eckey);
	buffer = OPENSSL_malloc(buf_len);
	pp = buffer;
	if (ECDSA_sign(0, digest, dgstlen, pp, &buf_len, eckey) == 0)
		/* error */

	ret = ECDSA_do_verify(digest, 32, sig, eckey);

	ret = ECDSA_verify(0, digest, 32, buffer, buf_len, eckey);
}