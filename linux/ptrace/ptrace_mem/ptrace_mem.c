#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <getopt.h>
#include "logging.h"
#include "autofree.h"
#include "ctype.h"
#include "hex.h"
#include "common.h"

#define PTRACE_READ     0
#define PTRACE_WRITE    1

struct PtraceMem {
    pid_t pid;
    size_t vaddr;
    size_t count;
    size_t value;
    int flags;
};

static const char *help = 
"Usage: ptrace_mem <--pid pid> <--vaddr vaddr> [<--count N>|<--write val>]\n"
"\t-p, --pid pid\t\tThe pid of the process to be whatched\n"
"\t-v, --vaddr vaddr\tThe begin virutal address we want to access.\n"
"\t-c, --count N\t\tRead only N count memeory.\n"
"\t-w, --write Val\t\tWrite Val to memeory.\n";

static int check_ptracemem(struct PtraceMem *ptracemem)
{
    int ret = 0;
    int read = ptracemem->flags != PTRACE_WRITE;

    LOG_COND_CHECK((ptracemem->pid == 0), -1, Help);
    LOG_COND_CHECK((ptracemem->vaddr == 0), -1, Help);
    LOG_COND_CHECK((ptracemem->count == 0 && read), -1, Help);

    return ret;

Help:
    printf("Invalid input argument\n");
    printf("%s", help);
    return ret;
}

static void parse_ptracemem(int argc, char *argv[], struct PtraceMem *ptracemem)
{
    struct option opts[] = {
        {"pid",     required_argument,  0,  'p'},
        {"vaddr",   required_argument,  0,  'v'},
        {"count",   required_argument,  0,  'c'},
        {"write",   required_argument,  0,  'w'},
        {"help",    no_argument,        0,  'h'}
    };

    int arg = 0; int index = 0;

    while ((arg = getopt_long(argc, argv, "p:o:c:h", opts, &index)) != -1) {
        switch(arg) {
            case 'p':
                ptracemem->pid = atoi(optarg);
                break;
            case 'v':
                ptracemem->vaddr = strtoul(optarg, NULL, 0);
                break;
            case 'c':
                ptracemem->count = strtoul(optarg, NULL, 0);
                break;
            case 'w':
                ptracemem->value = strtoul(optarg, NULL, 0);
                ptracemem->flags = PTRACE_WRITE;
                break;
            case 'h':
                printf("%s",help);
                exit(0);
                break;
            default: 
                break;
        }
    }
}

static int ptrace_pid(pid_t pid)
{
    int ret;

    ret = ptrace(PTRACE_ATTACH, pid, 0, 0);
    LOG_COND_CHECK((ret < 0), ret, failed);

    waitpid(pid, NULL, 0);//wait for the attach to succeed.

failed:
    return ret;
}

static int unptrace_pid(pid_t pid)
{
    int ret;

    ret = ptrace(PTRACE_DETACH, pid, 0, 0);
    LOG_COND_CHECK((ret < 0), ret, failed);

failed:
    return ret;
}

static int dump_mem(struct PtraceMem *pmem)
{
    long data;
    autofree u8 *buff;
    size_t index;
    size_t size = ALIGN_ULONG(pmem->count);
    int ret = 0;

    buff = malloc(size);
    LOG_COND_CHECK((buff == NULL), -1, failed);

    for (index = 0; index < size/sizeof(long); index++) {
        data = ptrace(PTRACE_PEEKTEXT, pmem->pid, pmem->vaddr + index*8, NULL);
        LOG_COND_CHECK((data < 0), -1, failed);
        memcpy(&buff[index*8], (u8 *)&data, sizeof(data));
    }

    hex_mem(pmem->vaddr, buff,  size);
 
failed:
    return ret;
}

static int write_mem(struct PtraceMem *pmem)
{
    long pret;
    int ret;

    pret = ptrace(PTRACE_POKEDATA, pmem->pid, pmem->vaddr, pmem->value);
    LOG_COND_CHECK((pret < 0), -1, failed);

failed:
    return ret;
}

int main(int argc, char *argv[])
{
    struct PtraceMem ptracemem = {0,0,0,0,0};
    int ret;

    parse_ptracemem(argc, argv, &ptracemem);
    ret = check_ptracemem(&ptracemem);
    LOG_COND_CHECK((ret < 0), ret, failed);
    
    ret = ptrace_pid(ptracemem.pid);
    LOG_COND_CHECK((ret < 0), ret, failed);


    if (ptracemem.flags == PTRACE_READ)
        dump_mem(&ptracemem);

    if (ptracemem.flags == PTRACE_WRITE)
        write_mem(&ptracemem);

    unptrace_pid(ptracemem.pid);

failed:
    return ret;
}