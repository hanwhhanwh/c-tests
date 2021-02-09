/*
 * dump back-trace example
 * @date : 2021-02-09
 * @author : hbesthee@naver.com
reference:
	https://www.geeksforgeeks.org/core-dump-segmentation-fault-c-cpp/
	https://www.minzkn.com/moniwiki/wiki.php/backtrace
build:
	gcc dump_trace.c -o dump_trace -fno-omit-frame-pointer -rdynamic
*/
#include <execinfo.h>
#include <signal.h>


void dump_backtrace(void)
{
    /* IMPORTANT

        gcc need compile option "-fno-omit-frame-pointer"
        gcc optional linker option "-rdynamic"

    */
    void *s_backtrace_buffer[16];
    char **s_backtrace_symbols;
    int s_backtrace_size;
    int s_backtrace_index;

    s_backtrace_size = backtrace(
        (void **)(&s_backtrace_buffer[0]),
        (int)(sizeof(s_backtrace_buffer) / sizeof(void *))
    );
    if(s_backtrace_size <= 0) {
        s_backtrace_symbols = (char **)0;
    }
    else {
        s_backtrace_symbols = backtrace_symbols(
            (void * const *)(&s_backtrace_buffer[0]),
            s_backtrace_size
        );
    }

    (void)fprintf(stderr, "backtrace() returned %d addresses\n", s_backtrace_size);
    for(s_backtrace_index = 0;s_backtrace_index < s_backtrace_size;s_backtrace_index++) {
        (void)fprintf(
            stderr,
            "%02d - %p - %s\n",
            s_backtrace_index + 1,
            s_backtrace_buffer[s_backtrace_index],
            (s_backtrace_symbols == ((char **)0)) ? "<unknown symbol>" : s_backtrace_symbols[s_backtrace_index]
        );
    }
    free((void *)s_backtrace_symbols);
}


void my_signal_handler(int s_signal)
{
	switch(s_signal) {
		case SIGILL:
		case SIGABRT:
		case SIGBUS:
		case SIGSTKFLT:
		case SIGFPE:
		case SIGSEGV:
			dump_backtrace();
			break;
	}

	signal(s_signal, my_signal_handler); /* 자기자신의 Signal 을 재귀적으로 처리하기 위해서 */
}


int main(int argc, char *argv[])
{
	char *str; 

	/* Stored in read only part of data segment */
	str = "GfG";     

	/* 주요 비정상 종료와 관련한 Signal에 handler를 등록합니다. */
	signal(SIGILL, my_signal_handler);
	signal(SIGABRT, my_signal_handler);
	signal(SIGBUS, my_signal_handler);
	signal(SIGSTKFLT, my_signal_handler);
	signal(SIGFPE, my_signal_handler);
	signal(SIGSEGV, my_signal_handler);

	/* Problem:  trying to modify read only memory */
	*(str+1) = 'n'; 
	return 0;
}