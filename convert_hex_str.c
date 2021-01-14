/**
 * Convert hex string to buffer example
 * @author hbesthee@naver.com
 * @date 2021-01-14
 */
#include <stdio.h>
#include <string.h>


static void print_ptr(const char *strMsg, unsigned char *ptr, int len)
{
    int index = 0;
    printf(strMsg);
    for ( ; index < len ; index ++)
        printf("%02x", ptr[index]);
    printf("\n");
}


static int str_to_buf(unsigned char *buf, const char *str)
{
	int str_len = strlen(str);
	if (str_len == 0)
		return 0;

	int count = 0;
	int index = 0;
	for ( ; index < str_len ; index ++)
	{
		buf[count] = (str[index] >= '0' && str[index] <= '9') ? str[index] - '0' : (str[index] & 0x3f) - 'A' + 10;
		index++;
		if ( index < str_len )
		{
			buf[count] = 0;
			break;
		}
		buf[count] |= ((str[index] >= '0' && str[index] <= '9') ? str[index] - '0' : (str[index] & 0x3f) - 'A' + 10) << 8;
		count ++;
	}
	return count;
}


int main(int argc, char *argv[])
{
	unsigned char buf[512];
	int count;

	count = str_to_buf(buf, "aabbccddee");
	print_ptr("buf = ", buf, count);
}