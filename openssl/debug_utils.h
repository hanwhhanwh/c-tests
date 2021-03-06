/**
 * Utilities for debugging (print out)
 * @date : 2021-02-02
 * @author : hbesthee@naver.com
 */

 #define DEBUG_FUNC(fmt_str, ...)								\
	do {														\
		time_t timer; struct tm* t;								\
		timer = time(NULL); t = localtime(&timer);				\
		printf("[%4d-%02d-%02d %02d:%02d:%02d] " 				\
				"[%s:%s()] "fmt_str,							\
				t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,	\
				t->tm_hour, t->tm_min, t->tm_sec,				\
				__FILE__,__func__,##__VA_ARGS__);				\
	} while (0)

 #define DEBUG_MSG(fmt_str, ...)								\
	do {														\
		printf("  [%05d] ", __LINE__);							\
		printf(fmt_str,##__VA_ARGS__);							\
	} while (0)

 #define DEBUG_PTR(strMsg, ptr, len)							\
	do {														\
		if ((strMsg == NULL) || (ptr == NULL))					\
			break;												\
		int index = 0;											\
		printf("  [%05d] ", __LINE__);							\
		printf("%s = [%d] ", strMsg, len);						\
		for ( ; index < len ; index ++)							\
			printf("%02x", ptr[index]);							\
		printf("\n");											\
	} while (0)

 #define DEBUG_BIGNUM(strMsg, bn)									\
	do {															\
		if ((strMsg == NULL) || (bn == NULL))						\
		{															\
			fprintf(stdout, "  [%05d] BIGNUM is NULL", __LINE__);	\
			break;													\
		}															\
		int len = BN_num_bytes(bn);									\
		fprintf(stdout, "  [%05d] BIGNUM ", __LINE__);				\
		fprintf(stdout, "%s = [%d] ", strMsg, len);					\
		BN_print_fp(stdout, bn);									\
		fprintf(stdout, "\n");										\
	} while (0)


int hex2bin(unsigned char *dest_buf, int buf_len, const char *hex_str)
{
	int str_len = strlen(hex_str);
	if (str_len == 0)
		return 0;

	int count = 0;
	int index = 0;
	for ( ; count < buf_len ; index ++)
	{
		dest_buf[count] = ((hex_str[index] >= '0' && hex_str[index] <= '9') ? hex_str[index] - '0' : (hex_str[index] | 0x20) - 'a' + 10) << 4;
		index ++;
		if ( index >= str_len )
		{
			dest_buf[count] = 0;
			break;
		}
		dest_buf[count] |= (hex_str[index] >= '0' && hex_str[index] <= '9') ? hex_str[index] - '0' : (hex_str[index] | 0x20) - 'a' + 10;
		count ++;
	}
	return count;
}
