/**
 * integer pointer example
 * @date : 2021-01-12
 * @author : hbesthee@naver.com
 * gcc int_ptr.c -o int_ptr
 */
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
	unsigned char *buf;
	unsigned int *int_ptr;
	int index = 0;

	buf = malloc(20);
	for ( ; index < 20 ; index ++)
		buf[index] = index;
	int_ptr = (unsigned int *)buf;
	printf("first data = %08x\n", *int_ptr);
	free(buf);
}