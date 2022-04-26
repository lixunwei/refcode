#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <unistd.h>

static int child_trace()
{
    int ret;

    ret = ptrace(PTRACE_TRACEME, 0L, 0L, 0L);

    kill(getpid(), SIGSTOP);//We cannot ensure that the parent has traced the process before the child process calls execve. So that the child process stop itself.

    return ret;
}

int child_main()
{
    int ret;

    ret = child_trace(); 

    while(1) {
        printf("I'm child \n");
        sleep(2);
    };

}