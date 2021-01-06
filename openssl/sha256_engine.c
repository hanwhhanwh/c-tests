/**
 * SHA256 engine main source
 * @author hbesthee@naver.com
 * @date 2021-01-06
 * @reference : e_ossltest.c (OpenSSL test source)
 */
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>


static int digest_sha256_init(EVP_MD_CTX *ctx)
{
	printf("digest_sha256_init\n");
	//return SHA256_Init(data(ctx));
	return 1;
}


static int digest_sha256_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	printf("digest_sha256_update = %d : %s\n", count, data);
	// return SHA256_Update(data(ctx), data, (size_t)count);
	return 1;
}


static int digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	// int ret;
	// ret = SHA256_Final(md, data(ctx));

	// if (ret > 0) {
	// 	fill_known_data(md, SHA256_DIGEST_LENGTH);
	// }
	// return ret;

	printf("digest_sha256_final\n");
	memset(md, 0x41, SHA256_DIGEST_LENGTH);
	return 1;
}


static EVP_MD *_hidden_sha256_md = NULL;
static EVP_CIPHER *_hidden_aes_128_cbc = NULL;


static const EVP_MD *digest_sha256(void)
{
	if (_hidden_sha256_md == NULL) {
		EVP_MD *md;

		if ((md = EVP_MD_meth_new(NID_sha256, NID_sha256WithRSAEncryption)) == NULL
			|| !EVP_MD_meth_set_result_size(md, SHA256_DIGEST_LENGTH)
			|| !EVP_MD_meth_set_input_blocksize(md, SHA256_CBLOCK)
			|| !EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *) + sizeof(SHA256_CTX))
			|| !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
			|| !EVP_MD_meth_set_init(md, digest_sha256_init)
			|| !EVP_MD_meth_set_update(md, digest_sha256_update)
			|| !EVP_MD_meth_set_final(md, digest_sha256_final)
		) {
			EVP_MD_meth_free(md);
			md = NULL;
		}
		_hidden_sha256_md = md;
	}
	return _hidden_sha256_md;
}


static int se_digest_nids(const int **nids)
{
	static int digest_nids[2] = { 0, 0 };
	static int pos = 0;
	const EVP_MD *md;

	// if ((md = digest_md5()) != NULL)
	// 	digest_nids[pos++] = EVP_MD_type(md);
	// if ((md = digest_sha1()) != NULL)
	// 	digest_nids[pos++] = EVP_MD_type(md);
	if ((md = digest_sha256()) != NULL)
		digest_nids[pos++] = EVP_MD_type(md);
	// if ((md = digest_sha384()) != NULL)
	// 	digest_nids[pos++] = EVP_MD_type(md);
	// if ((md = digest_sha512()) != NULL)
	// 	digest_nids[pos++] = EVP_MD_type(md);
	digest_nids[pos] = 0;
	*nids = digest_nids;

	return pos;
}


static int se_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	int ok = 1;
	if (!digest) {
		/* We are returning a list of supported nids */
		return se_digest_nids(nids);
	}
	/* We are being asked for a specific digest */
	switch (nid) {
	// case NID_md5:
	// 	*digest = digest_md5();
	// 	break;
	// case NID_sha1:
	// 	*digest = digest_sha1();
	// 	break;
	case NID_sha256:
		*digest = digest_sha256();
		break;
	// case NID_sha384:
	// 	*digest = digest_sha384();
	// 	break;
	// case NID_sha512:
	// 	*digest = digest_sha512();
	// 	break;
	default:
		ok = 0;
		*digest = NULL;
		break;
	}
	return ok;
}


static void destroy_digests(void)
{
	EVP_MD_meth_free(_hidden_sha256_md);
	_hidden_sha256_md = NULL;
}


static void destroy_ciphers(void)
{
	// EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
	// EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
	_hidden_aes_128_cbc = NULL;
}


static int se_init(ENGINE *e)
{
    return 1;
}


static int se_finish(ENGINE *e)
{
    return 1;
}


static int se_destroy(ENGINE *e)
{
	destroy_digests();
	// destroy_ciphers();
	// ERR_unload_SE_strings();
	return 1;
}


#ifndef OPENSSL_NO_DYNAMIC_ENGINE

static int bind_helper(ENGINE * e, const char *id)
{
	if (!ENGINE_set_id(e, "SHA256")
			|| !ENGINE_set_name(e, "SHA256 engine")
			|| !ENGINE_set_digests(e, se_digests)
			// || !ENGINE_set_ciphers(e, se_ciphers)
			// || !ENGINE_set_RAND(e, se_rand_method())
			|| !ENGINE_set_init_function(e, se_init)
			|| !ENGINE_set_finish_function(e, se_finish)
			|| !ENGINE_set_destroy_function(e, se_destroy)
	) {
		return 0;
	}

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper);

#endif
