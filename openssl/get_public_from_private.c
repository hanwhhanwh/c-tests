/**
 * get public key from private key
 * @date : 2021-02-04
 * @author : hbesthee@naver.com

build : gcc get_public_from_private.c -o get_public_from_private -lcrypto -lssl
TEST :
# ./sign-test
 */
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


#include "debug_utils.h"


#define BUF_LEN				64


int main(int argc, char *argv[])
{
	int        ret, len;
	EC_KEY    *eckey;
	unsigned char priv[BUF_LEN];
	int priv_len = 0;
	const EC_GROUP *group;
	const BIGNUM *priv_key, *x, *y;
	const EC_POINT *pub_key = NULL;

	if (argc != 3)
	{
		printf("usage : %s [private key(hexa string)]\n", argv[0]);
		printf("  example : %s de4193614d7d93982a7c149e0d184c20c2d89e39ff9fac1363dab8a858c7c749\n", argv[0]);
		printf("\n");
		priv_len = hex2bin(priv, BUF_LEN, "de4193614d7d93982a7c149e0d184c20c2d89e39ff9fac1363dab8a858c7c749");
	}
	else
	{
		priv_len = hex2bin(priv, BUF_LEN, argv[1]);
	}
	DEBUG_PTR("priv", priv, priv_len);

	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL)
	{
		printf("error %d\n", __LINE__);
		return __LINE__;
	}

	group = EC_KEY_get0_group(eckey);
	priv_key = EC_KEY_get0_private_key(eckey);
	priv_key = BN_new();
	BN_bin2bn(priv, priv_len, priv_key);
	DEBUG_BIGNUM("priv_key", priv_key);
	EC_KEY_set_private_key(eckey, priv_key);
	pub_key = EC_POINT_new(group);
	// calc public key
	EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, NULL);
	EC_KEY_set_public_key(eckey, pub_key);

	// get x, y of public key
	x = BN_new();
	y = BN_new();
	if (EC_POINT_get_affine_coordinates_GFp(group, pub_key, x, y, NULL))
	{
		DEBUG_BIGNUM("pub_key->x", x);
		DEBUG_BIGNUM("pub_key->y", y);
	}
}