/**
 * OpenSSL AES GCM encrypt/decrypt example
 * @date : 2021-02-21
 * @author : hbesthee@naver.com
 * gcc aes_gcm.c -o aes_gcm
 * reference : https://gist.github.com/eliburke/24f06a1590d572e86a01504e1b38b27f
*/

#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>


#define AES_256_KEY_LENGTH      32
#define AES_256_KEY_LENGTH_BITS 256
#define AES_256_IVEC_LENGTH     12
#define AES_256_GCM_TAG_LENGTH  16


// encrypt plaintext.
// key, ivec and tag buffers are required, aad is optional
// depending on your use, you may want to convert key, ivec, and tag to NSData/NSMutableData
int aes256gcmEncrypt(unsigned char *ciphertext
					, const unsigned char *plaintext
					, int plaintext_len
					, const unsigned char *aad
					, int aad_len
					, const unsigned char *key
					, const unsigned char *ivec
					, unsigned char *tag)
{
	int status = 0;
	if (!ciphertext)
		return 0;
	
	// set up to Encrypt AES 256 GCM
	int numberOfBytes = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex (ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	
	// set the key and ivec
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_IVEC_LENGTH, NULL);
	EVP_EncryptInit_ex (ctx, NULL, NULL, key, ivec);
	
	// add optional AAD (Additional Auth Data)
	if (aad)
		status = EVP_EncryptUpdate( ctx, NULL, &numberOfBytes, aad, aad_len);
	
	unsigned char * ctBytes = [*ciphertext mutableBytes];
	EVP_EncryptUpdate (ctx, ciphertext, &numberOfBytes, plaintext, plaintext_len);
	status = EVP_EncryptFinal_ex (ctx, ctBytes+numberOfBytes, &numberOfBytes);
	
	if (status && tag) {
		status = EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, AES_256_GCM_TAG_LENGTH, tag);
	}
	EVP_CIPHER_CTX_free(ctx);
	return (status != 0); // OpenSSL uses 1 for success
}


// decrypt ciphertext.
// key, ivec and tag buffers are required, aad is optional
// depending on your use, you may want to convert key, ivec, and tag to NSData/NSMutableData
int aes256gcmDecrypt(unsigned char *plaintext
					, const unsigned char *ciphertext
					, int ciphertext_len
					, unsigned char *aad
					, int aad_len
					, const unsigned char *key
					, const unsigned char *ivec
					, unsigned char *tag)
{
	int status = 0;
	
	if (!ciphertext || !plaintext || !key || !ivec)
		return 0;
	
	if (!plaintext)
		return 0;
	
	// set up to Decrypt AES 256 GCM
	int numberOfBytes = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex (ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	
	// set the key and ivec
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_256_IVEC_LENGTH, NULL);
	status = EVP_DecryptInit_ex (ctx, NULL, NULL, key, ivec);
	
	// Set expected tag value. A restriction in OpenSSL 1.0.1c and earlier requires the tag before any AAD or ciphertext
	if (status && tag)
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_256_GCM_TAG_LENGTH, tag);
	
	// add optional AAD (Additional Auth Data)
	if (aad)
		EVP_DecryptUpdate(ctx, NULL, &numberOfBytes, aad, aad_len);
	
	status = EVP_DecryptUpdate (ctx, [*plaintext mutableBytes], &numberOfBytes, [ciphertext bytes], (int)[ciphertext length]);
	if (! status) {
		//DDLogError(@"aes256gcmDecrypt: EVP_DecryptUpdate failed");
		return 0;
	}
	EVP_DecryptFinal_ex (ctx, NULL, &numberOfBytes);
	EVP_CIPHER_CTX_free(ctx);
	return (status != 0); // OpenSSL uses 1 for success
}


int main(int argc, char *argv[])
{
}