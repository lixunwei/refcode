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


struct PtraceMem {
    pid_t pid;
    size_t vaddr;
    size_t count;
};

static const char *help = 
"Usage: ptrace_mem <--pid pid> <--vaddr vaddr> <--count N>\n"
"\t-p, --pid pid\t\tThe pid of the process to be whatched\n"
"\t-v, --vaddr vaddr\tThe begin virutal address we want to access.\n"
"\t-c, --count N\t\tRead only N count memeory.\n";

static int check_ptracemem(struct PtraceMem *ptracemem)
{
    if (ptracemem->pid == 0 || ptracemem->count == 0 || ptracemem->vaddr == 0) {
        printf("Invalid input argument\n");
        printf("%s", help);
        return -1;
    }
    
    return 0;
}

static void parse_ptracemem(int argc, char *argv[], struct PtraceMem *ptracemem)
{
    struct option opts[] = {
        {"pid",     required_argument,  0,  'p'},
        {"vaddr",   required_argument,  0,  'v'},
        {"count",   required_argument,  0,  'c'},
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

failed:
    return ret;
}

static int dump_mem(struct PtraceMem *pmem)
{
    unsigned long data;
    autofree u8 *buff;
    size_t index;
    size_t size = ALIGN_PAGE(pmem->count);
    int ret = 0;

    buff = malloc(size);
    LOG_COND_CHECK((buff == NULL), -1, failed);

    for (index = 0; index < size/sizeof(long); index++) {
        data = ptrace(PTRACE_PEEKTEXT, pmem->pid, pmem->vaddr + index*8, NULL);
        memcpy(&buff[index*8], (u8 *)&data, sizeof(data));
    }

    hex_mem(pmem->vaddr, buff,  size);
 
failed:
    return ret;
}

int main(int argc, char *argv[])
{
    struct PtraceMem ptracemem = {0,0,0};
    int ret;

    parse_ptracemem(argc, argv, &ptracemem);
    ret = check_ptracemem(&ptracemem);
    LOG_COND_CHECK((ret < 0), ret, failed);
    
    ret = ptrace_pid(ptracemem.pid);
    LOG_COND_CHECK((ret < 0), ret, failed);

    dump_mem(&ptracemem);

failed:
    return ret;
}