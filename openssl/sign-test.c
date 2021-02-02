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
	const EC_GROUP *group;
	const BIGNUM *priv_key;
	const EC_POINT *pub_key = NULL;

	for (ret = 0 ; ret < 32 ; ret ++)
		digest[ret] = ret;

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
	// *priv_der = malloc(512);
	// ret = i2d_ECPrivateKey(eckey, priv_der);
	// if (ret == 0)
	// {
	// 	printf("error %d", __LINE__);
	// 	ret = ERR_get_error();
	// 	ERR_error_string_n(ret, err_msg, 512);
	// 	printf(" : %d = %s\n", ret, err_msg);
	// 	return __LINE__;
	// }
	// DEBUG_PTR("priv_der", *priv_der, ret);
	// free(*priv_der);
	group = EC_KEY_get0_group(eckey);
	priv_key = EC_KEY_get0_private_key(eckey);
	DEBUG_BIGNUM("priv_key", priv_key);

	pub_key = EC_KEY_get0_public_key(eckey);
	BN_CTX *ctx = NULL;
	ctx = BN_CTX_new();
	unsigned char *pub_data = EC_POINT_point2hex(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, ctx);
	DEBUG_MSG("pub_data = %s\n", pub_data);
	BN_CTX_free(ctx);

	int nSize = i2o_ECPublicKey(eckey, NULL);
	DEBUG_MSG("pub key need buf = %d\n", nSize);
	unsigned char pub_key_buf[512];
	unsigned char *ptr_pub_key = &pub_key_buf[0];
	nSize = i2o_ECPublicKey(eckey, &ptr_pub_key);
	DEBUG_PTR("ptr_pub_key", ptr_pub_key, nSize);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

	BN_dec2bn(&x, "1024");
	DEBUG_BIGNUM("1024", x);
	ret = BN_bn2lebinpad(x, digest, 8);
	DEBUG_PTR("1024 ptr", digest, ret);

	if (EC_POINT_get_affine_coordinates_GFp(group, pub_key, x, y, NULL))
	{
		DEBUG_BIGNUM("pub_key->x", x);
		DEBUG_BIGNUM("pub_key->y", y);
	}

	ECParameters_print_fp(stdout, eckey);

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