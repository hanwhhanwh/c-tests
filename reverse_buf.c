/**
 * reverse buffer example
 * @author hbesthee@naver.com
 * @date 2021-02-02
 *
 * gcc reverse_buf.c -o reverse_buf
 */
#include <stdio.h>
#include <string.h>


#include "openssl/debug_utils.h"


void revers_buf(unsigned char *buf, int buflen)
{
	int index = 0, len = buflen / 2;
	unsigned char tmp;
	for ( ; index < len ; index ++)
	{
		tmp = buf[index];
		buf[index] = buf[buflen - 1 - index];
		buf[buflen - 1 - index] = tmp;
	}
}


int main(int argc, char *argv[])
{
	unsigned char buf[512];
	int index = 0, buflen = 512, count;

	for ( ; index < buflen ; index ++)
		buf[index] = index;

	DEBUG_PTR("buf", buf, 16);
	revers_buf(buf, 8);
	DEBUG_PTR("buf", buf, 8);
	revers_buf(buf, 5);
	DEBUG_PTR("buf", buf, 8);
}