/*
 * oezganEngine.c
 *
 *  Created on: Sep 29, 2015
 *      Author: oezgan
 */
 /* ====================================================================
 * Copyright (c) 1998-2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <string.h>
#include "oezganEngine.h"
//new include
#include "wrapper.h"

static const char *engine_oezgan_id = "oezgan";
static const char *engine_oezgan_name = "oezgan engine by Fraunhofer FKIE";

static int oezgan_digest_ids[] = { NID_sha256};
static int oezgan_engine_digest_selector(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);


int oezgan_init(ENGINE *e) {
	printf("Oezgan Engine Initializatzion!\n");
	return 786;
}

static int oezgan_engine_sha256_init(EVP_MD_CTX *ctx);
static int oezgan_engine_sha256_update(EVP_MD_CTX *ctx,const void *data,size_t count);
static int oezgan_engine_sha256_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int oezgan_engine_sha256_final(EVP_MD_CTX *ctx,unsigned char *md);
static int oezgan_engine_sha256_cleanup(EVP_MD_CTX *ctx);

int oezgan_engine_ecdsa_sign_setup (EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
		BIGNUM **r);

int oezgan_engine_ecdsa_do_verify (const unsigned char *dgst, int dgst_len,
		const ECDSA_SIG *sig, EC_KEY *eckey);

static ECDSA_SIG *oezgan_engine_ecdsa_sign (const unsigned char *dgst, int dgst_len,
		const BIGNUM *kinv, const BIGNUM *rp,
		EC_KEY *in_eckey);




static int oezgan_engine_compute_ecdh_key(void * key, size_t outlen, const EC_POINT *pubkey,
		EC_KEY *ecdh,void *(*KDF) (const void *in,
				size_t inlen, void *out,
				size_t *outlen));


static ECDSA_SIG *oezgan_engine_ecdsa_sign (const unsigned char *dgst, int dgst_len,
		const BIGNUM *kinv, const BIGNUM *rp,
		EC_KEY *in_eckey) {
	printf("oezgan engine ecdsa sign digest \n");


	int sig_len = 0;
	//convert privatekey
	int pkeyLen = i2d_ECPrivateKey(in_eckey,NULL);
	const BIGNUM* bignum = EC_KEY_get0_private_key(in_eckey);
	unsigned char *ucBuf, *uctempBuf;
	pkeyLen = BN_bn2mpi(bignum, NULL);
	ucBuf = (unsigned char *)malloc(pkeyLen+1);
	uctempBuf = ucBuf;
	//Note that this function modifies the uctempBuf as
	// uctempBuf = uctempBuf + pkeyLen
	BN_bn2mpi(bignum, uctempBuf);


	int pubkey_len = i2o_ECPublicKey(in_eckey,NULL);
	unsigned char * out_sig;
	out_sig = malloc(sizeof(unsigned char)*pubkey_len);
	//convert pubkey
	unsigned char* pubkey = malloc(sizeof(unsigned char)*pubkey_len);
	int er = i2o_ECPublicKey(in_eckey,&pubkey);
	pubkey -= pubkey_len;
	//Create a DER encoded signature

	ECDSA_SIG * ret_sig;
	ret_sig = d2i_ECDSA_SIG(NULL,&out_sig,sig_len);
	out_sig -= sig_len;
	return ret_sig;
}

int oezgan_engine_ecdsa_sign_setup (EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
		BIGNUM **rp)
{
	return 1;
}

int oezgan_engine_ecdsa_do_verify (const unsigned char *digest, int digest_len,
		const ECDSA_SIG *ecdsa_sig, EC_KEY *eckey) {
	printf("oezgan engine verifying function\n");
	int res = 0;
	int er = 0;
	//convert ECDSA_SIG to unsigned char
	int sig_len = i2d_ECDSA_SIG(ecdsa_sig,NULL);
	unsigned char * sign = malloc(sizeof(unsigned char)*sig_len);
	er = i2d_ECDSA_SIG(ecdsa_sig,&sign);
	sign -= sig_len;


	//convert EC_Key to unsigned char

	int pubkey_len = i2o_ECPublicKey(eckey,NULL);
	unsigned char* pubkey = malloc(sizeof(unsigned char)*pubkey_len);
	er = i2o_ECPublicKey(eckey,&pubkey);
	pubkey -= er;
	if(er == 0) {
		printf("\n Could not convert EC_KEY error:%d\n",er);
		return er;
	}
	res =99;
	printf("oezgan ecdsa verfiy end! result %d\n",res);
	return res;
}






//SHA 256
static int oezgan_engine_sha256_init(EVP_MD_CTX *ctx) {
	ctx->update = &oezgan_engine_sha256_update;
	printf("initialized! SHA256\n");
	return 1;
}

static int oezgan_engine_sha256_update(EVP_MD_CTX *ctx,const void *data,size_t count) {
	printf("SHA256 update \n");
	unsigned char * digest256 = (unsigned char*) malloc(sizeof(unsigned char)*32);
	memset(digest256,2,32);
	count = 32;
	ctx->md_data = digest256;
	return 1;
}
static int oezgan_engine_sha256_final(EVP_MD_CTX *ctx,unsigned char *md) {
	printf("SHA256 final size of EVP_MD: %d\n", sizeof(EVP_MD));
	memcpy(md,(unsigned char*)ctx->md_data,32);
	return 1;
}
int oezgan_engine_sha256_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
	printf("Copy SHA256\n");
	if (to->md_data && from->md_data) {
		memcpy(to->md_data, from->md_data,sizeof(from->md_data));
	}
	return 1;
}

static int oezgan_engine_sha256_cleanup(EVP_MD_CTX *ctx) {
	printf("SHA256 cleanup\n");
	if (ctx->md_data)
		memset(ctx->md_data, 0, 32);
	return 1;
}

int get_random_bytes(unsigned char *buf, int num) {
	printf("oezgan engine random length %d\n", num);
	getRandomBytes_C(buf, num);
	return 99;
}
int oezgan_random_status(void)
{
	return 1;
}
RAND_METHOD oezgan_random_method = {
		NULL,                       /* seed */
		get_random_bytes,
		NULL,                       /* cleanup */
		NULL,                       /* add */
		get_random_bytes,
		oezgan_random_status,
};



static EVP_MD oezgan_engine_sha256_method= 	{
		NID_sha256,
		NID_undef,
		32,
		EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,
		oezgan_engine_sha256_init,
		oezgan_engine_sha256_update,
		oezgan_engine_sha256_final,
		oezgan_engine_sha256_copy,
		oezgan_engine_sha256_cleanup,
		/* FIXME: prototype these some day */
		NULL,
		NULL,
		{NID_undef, NID_undef, 0, 0, 0},
		64, /*Block Size*/
		32, /* how big does the ctx->md_data need to be */
		/* control function */
		NULL,
} ;

ECDH_METHOD oezgan_engine_ecdh_method = {
		"Oezgan Engine ECDH Method",
		oezgan_engine_compute_ecdh_key,
# if 0
		NULL,
		NULL,
# endif
		0,
		NULL,
};
static int oezgan_engine_compute_ecdh_key(void * key, size_t outlen, const EC_POINT *pubkey,
		EC_KEY *eckey, void *(*oezgan_ecdh_kdf) (const void *in, size_t inlen, void *out,
				size_t *outlen)) {
	printf("Oezgan Engine ECDH Method\n");

	EC_GROUP *group = EC_KEY_get0_group(eckey);
	//convert pubkey
	int pubkey_len = EC_POINT_point2oct(group, pubkey,
			POINT_CONVERSION_UNCOMPRESSED,
			NULL, 0, NULL);
	unsigned char * pubkey_buf = malloc(sizeof(unsigned char)*pubkey_len);
	pubkey_len = EC_POINT_point2oct(group, pubkey,
			POINT_CONVERSION_UNCOMPRESSED,
			pubkey_buf, pubkey_len, NULL);

	//convert private key
	const BIGNUM* prikey_bn = BN_new();
	prikey_bn = EC_KEY_get0_private_key(eckey);
	int privkey_len =  BN_num_bytes(prikey_bn);
	unsigned char * privkey_buf = malloc(sizeof(unsigned char)*privkey_len);
	BN_bn2bin(prikey_bn, privkey_buf);

	memset(key,3,pubkey_len);
	outlen = pubkey_len;

	free(privkey_buf);
	free(pubkey_buf);

	printf("Oezgan engine ECDH method End returning: %d!\n", outlen);

	return outlen;
}

static ECDSA_METHOD oezgan_engine_ecdsa_method = {
		"Oezgan engine ECDSA method",
		oezgan_engine_ecdsa_sign,
		oezgan_engine_ecdsa_sign_setup,
		oezgan_engine_ecdsa_do_verify,
# if 0
		NULL,                       /* init */
		NULL,                       /* finish */
# endif
		0,  						/* flags */
		NULL                        /* app_data */
};

static int oezgan_engine_digest_selector(ENGINE *e, const EVP_MD **digest,
		const int **nids, int nid) {
	int ok = 1;
	if (!digest) {
		*nids = oezgan_digest_ids;
		return 2;
	}
	if (nid == NID_sha256) {
		*digest = &oezgan_engine_sha256_method;
	}
	else {
		ok = 0;
		*digest = NULL;
	}
	return ok;
}

int bind_helper(ENGINE * e, const char *id)
{
	if (!ENGINE_set_id(e, engine_oezgan_id) ||
			!ENGINE_set_name(e, engine_oezgan_name) ||
			!ENGINE_set_RAND(e, &oezgan_random_method) ||
			!ENGINE_set_init_function(e, oezgan_init) ||
			!ENGINE_set_digests(e, &oezgan_engine_digest_selector) ||
			!ENGINE_set_ECDH(e, &oezgan_engine_ecdh_method) ||
			!ENGINE_set_ECDSA(e, &oezgan_engine_ecdsa_method)
	)
		return 0;
	return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);