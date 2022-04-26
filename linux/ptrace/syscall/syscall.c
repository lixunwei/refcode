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
#include "childprocess.h"
#include "logging.h"

int child_setup()
{
    pid_t pid;
    int ret = 0;

    pid = fork();
    LOG_COND_CHECK((pid < 0), -1, failed);

    if (pid == 0) {
        child_main();
    }

    ret = pid;

failed:
    return ret;
}


int waitchild(pid_t pid)
{
    int status;
    pid_t sigpid;

    while(waitpid(pid, &status, WSTOPPED) < 0) {//we fisrt stop the child process so that the parent process can trace the child process before child process starts to execute execve.
        printf("Error\n");
    }

    printf("child signal = %x\n", status);

    ptrace(PTRACE_ATTACH, pid, 0, 0);
    ptrace(PTRACE_SYSCALL, pid, 0, 0);

    //ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACEFORK);
    //ptrace(PTRACE_INTERRUPT, pid, 0, 0);
    //ptrace(PTRACE_CONT, pid, 0, 0);

    while(1) {
        sigpid = waitpid(pid, &status, WSTOPPED);//waiting for a signal from a child process!
        printf("loop signal: %x\n", status);
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }
}

int main(int argc, char *argv[])
{
    pid_t child;
    int ret = 0;

    child = child_setup();
    printf("child pid = %d\n", child);
    LOG_COND_CHECK((child <= 0), -1, failed);

    waitchild(child);

failed:
    return ret;
}


