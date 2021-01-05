/*
 * engineTester.c
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

/*openssl*/
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>

int main(int argc, const char* argv[] ) {

	OpenSSL_add_all_algorithms();

	ERR_load_crypto_strings();

	ENGINE_load_dynamic();
	ENGINE *oezgan_engine = ENGINE_by_id("oezgan");

	if( oezgan_engine == NULL )
	{
		printf("Could not Load Oezgan Engine!\n");
		exit(1);
	}
	printf("Oezgan Engine successfully loaded\n");

	int init_res = ENGINE_init(oezgan_engine);
	printf("Engine name: %s init result : %d \n",ENGINE_get_name(oezgan_engine), init_res);
	ENGINE_set_default_RAND(oezgan_engine);

	unsigned char * rand_buf= new unsigned char[5];
	int err = RAND_bytes(rand_buf,5);
	for(int i= 0; i < 5; i++) {
		printf("%x",rand_buf[i]);
	}
	printf("\n");

	char * str = "Fraunhofer FKIE Wachtberg!";
	int str_len =  26;
	int er = ENGINE_set_default_digests(oezgan_engine);
	printf("ENGINE SETTING DEFAULT DIGESTS %d\n",er);

	unsigned char * digest = new unsigned char[32];
	unsigned int digestSize = -1;

	EVP_MD_CTX *evp_ctx;
	evp_ctx = EVP_MD_CTX_create();
	er = EVP_DigestInit_ex(evp_ctx, EVP_sha256(),oezgan_engine);
	printf("Digest INIT %d\n",er);
	er = EVP_DigestUpdate(evp_ctx, (unsigned char*)str, str_len);
	printf("Digest Update %d\n",er);
	er = EVP_DigestFinal(evp_ctx, digest, &digestSize);
	printf("Digest Final %d Digest size:%d\n",er,digestSize);
	for(int i= 0; i< digestSize; i++) {
		printf("%x", digest[i]);
	}
	printf("\n");
	EVP_MD_CTX_destroy(evp_ctx);

	er = ENGINE_set_default_ECDH(oezgan_engine);
	printf("ENGINE SETTING DEFAULT ECDH %d\n ",er);

	FILE* fp = fopen("./ownPrivkey.pem", "r");
	if (fp == NULL) {
		printf( "Could not open private key file\n");
		exit(1);
	}
	EVP_PKEY *privateKey;
	privateKey= PEM_read_PrivateKey(fp, NULL, 0, NULL);
	if ((privateKey) == NULL) {
		printf("Could not extract private key from file\n");
		exit(1);
	}
	fclose(fp);

	EC_KEY *eckey;
	eckey = EC_KEY_new();
	ECDSA_SIG * ecdsa_sig;
	ecdsa_sig = ECDSA_SIG_new();
	eckey = EVP_PKEY_get1_EC_KEY(privateKey);

	EC_GROUP *ec_group;
	ec_group = EC_GROUP_new_by_curve_name(NID_brainpoolP384r1);
	const EC_POINT* pub_key;
	pub_key = EC_KEY_get0_public_key(eckey);



	unsigned char agreed_value[200];
	EC_KEY *ecdh;
	ecdh = EC_KEY_new();
	EC_KEY_set_group(ecdh, ec_group);
	er = EC_KEY_set_private_key(ecdh, EC_KEY_get0_private_key(eckey));



	int agreed_value_len = ECDH_compute_key(agreed_value, 200,pub_key, ecdh, NULL);

	printf("Oezgan engine Agreed Value: %d\n",agreed_value_len);
	for(int i= 0; i < agreed_value_len; i++) {
		printf("%x", agreed_value[i]);
	}
	printf("\n");

	er = ENGINE_set_default_ECDSA(oezgan_engine);
	printf("\nENGINE SETTING DEFAULT ECDSA:%d\n",er);

	unsigned char *sig = new unsigned char[256];
	unsigned int sigsize;
	ECDSA_sign(0,digest,digestSize,sig,&sigsize,eckey);
	printf("Signature size:%d \n",sigsize);
	for(int i=0; i <sigsize;i++) {
		printf("%x",sig[i]);
	}
	printf("\n");
	printf("Now verifying!\n");

	BIO* bio_in;
	bio_in = BIO_new_file("./ownCert.pem", "r");
	if (bio_in == NULL) {
		printf("could not read public key file\n");
		exit(1);

	}
	X509 *certificate;
	certificate = X509_new();
	if (PEM_read_bio_X509(bio_in, &certificate, 0, NULL) == NULL) {
		printf("could not read  certificate from public key file\n");
		exit(1);
	}
	EVP_PKEY *pubKey;
	pubKey = X509_get_pubkey(certificate);
	EC_KEY* eckey_pub;
	eckey_pub = EVP_PKEY_get1_EC_KEY(pubKey);

	int	result = ECDSA_do_verify(digest, digestSize,
			ecdsa_sig, eckey_pub);
	printf("Verify result %d\n", result);


	EC_KEY_free(eckey);
	EC_GROUP_free(ec_group);
	EC_KEY_free(ecdh);
	X509_free(certificate);
	BIO_free_all(bio_in);

	free(rand_buf);
	return 0;
}