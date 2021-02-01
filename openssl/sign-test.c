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


#include "debug_utils.h"


int main(int argc, char *argv[])
{
	int        ret;
	ECDSA_SIG *sig;
	EC_KEY    *eckey;
	unsigned char digest[512];
	unsigned char err_msg[512];
	unsigned char **priv_der;
	int dgstlen = 32;

	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL)
	{
		/* error */
		printf("error %d\n", __LINE__);
		return __LINE__;
	}
	if (EC_KEY_generate_key(eckey) == 0)
	{
		/* error */
		printf("error %d\n", __LINE__);
		return __LINE__;
	}
	*priv_der = malloc(512);
	ret = i2d_ECPrivateKey(eckey, priv_der);
	if (ret == 0)
	{
		printf("error %d", __LINE__);
		ret = ERR_get_error();
		ERR_error_string_n(ret, err_msg, 512);
		printf(" : %d = %s\n", ret, err_msg);
		return __LINE__;
	}
	DEBUG_PTR("priv_der", *priv_der, ret);
	free(*priv_der);

	sig = ECDSA_do_sign(digest, 32, eckey);
	if (sig == NULL)
	{
		/* error */
		printf("error %d\n", __LINE__);
		return __LINE__;
	}
	DEBUG_PTR("digest", digest, dgstlen);

	unsigned char *buffer, *pp;
	int buf_len;

	buf_len = ECDSA_size(eckey);
	buffer = OPENSSL_malloc(buf_len);
	DEBUG_PTR("buffer", buffer, buf_len);
	pp = buffer;
	if (ECDSA_sign(0, digest, dgstlen, pp, &buf_len, eckey) == 0)
	{
		/* error */
		printf("error %d\n", __LINE__);
		return __LINE__;
	}
	DEBUG_PTR("digest2", digest, dgstlen);

	ret = ECDSA_do_verify(digest, 32, sig, eckey);
	if (ret == 0)
	{
		/* error */
		printf("error %d\n", __LINE__);
		return __LINE__;
	}
	DEBUG_MSG("ECDSA_do_verify ret = %d\n", ret);
	ret = ECDSA_verify(0, digest, 32, buffer, buf_len, eckey);
	if (ret == 0)
	{
		/* error */
		printf("error %d\n", __LINE__);
		return __LINE__;
	}
	DEBUG_MSG("ECDSA_verify ret = %d\n", ret);
}