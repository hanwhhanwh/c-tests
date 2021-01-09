/**
 * MD5 engine tester
 * @date : 2021-01-08
 * @author : hbesthee@naver.com
 * 참고: https://0x616b616d61.tistory.com/entry/Linux-C-md5-hash-생성-openssl-이용
 */
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h> // for generate md5 hash
 

int get_MD5(unsigned char* digest, char *strMsg)
{
	MD5_CTX context;

	MD5_Init(&context);
	MD5_Update(&context, strMsg, strlen(strMsg));
	return MD5_Final(digest, &context);
}
 

void print_usage()
{
	printf("Usage: md5_tester <Origianl Text>\n");
}


int main(int argc, char *argv[])
{
	unsigned char digest[MD5_DIGEST_LENGTH]; // #define MD5_DIGEST_LENGTH    16
	int index = 0, ret = 0;

	printf("argc = %d\n", argc);
	if (argc < 1)
	{
		print_usage();
		return 0;
	}

	ret = get_MD5(digest, argv[1]);
	printf("ret = %d\n", ret);
	if (ret == 1)
	{ // 결과를 출력합니다.
		printf("MD5 = ");
		for ( ; index < MD5_DIGEST_LENGTH ; index ++ )
			printf("%02x", digest[index]);
		printf("\n");
	}
	return ret;
}