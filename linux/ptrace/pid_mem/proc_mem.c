#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
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

#define PROCMEM_READ      0
#define PROCMEM_WRITE     1

struct PIDMem {
    int pid;
    size_t vaddr;
    size_t count;
    size_t value;
    int flags;
};

static const char *help = 
"Usage: proc_mem <--pid pid> <--vaddr vaddr> <--count N>\n"
"\t-p, --pid pid\t\tThe pid of the process to be whatched\n"
"\t-v, --vaddr vaddr\tThe begin virutal address we want to access.\n"
"\t-c, --count N\t\tRead only N count memeory.\n"
"\t-w, --write Val\t\tWrite Val to memeory.\n";

static int check_pidmem(struct PIDMem *pidmem)
{
    int ret = 0;
    int read = pidmem->flags != PROCMEM_WRITE;

    LOG_COND_CHECK((pidmem->pid == 0), -1, Help);
    LOG_COND_CHECK((pidmem->vaddr == 0), -1, Help);
    LOG_COND_CHECK((pidmem->count == 0 && read), -1, Help);

    return ret;

Help:
    printf("Invalid input argument\n");
    printf("%s", help);
    return ret;
}

static void parse_pidmem(int argc, char *argv[], struct PIDMem *pidmem)
{
    struct option opts[] = {
        {"pid",     required_argument,  0,  'p'},
        {"vaddr",   required_argument,  0,  'v'},
        {"count",   required_argument,  0,  'c'},
        {"write",   required_argument,  0,  'w'},
        {"help",    no_argument,        0,  'h'}
    };

    int arg = 0;
    int index = 0;

    while ((arg = getopt_long(argc, argv, "p:v:c:w:h", opts, &index)) != -1) {
        switch(arg) {
            case 'p':
                pidmem->pid = atoi(optarg);
                break;
            case 'v':
                pidmem->vaddr = strtoul(optarg, NULL, 0);
                break;
            case 'c':
                pidmem->count = strtoul(optarg, NULL, 0);
                break;
            case 'w':
                pidmem->value = strtoul(optarg, NULL, 0);
                pidmem->flags = PROCMEM_WRITE;
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

static void attach_pid(int pid)
{
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    waitpid(pid, NULL, 0);//wait for the attach to succeed.
}

static int mem_rw(struct PIDMem *pidmem)
{
    char mempath[32];
    autoclose int fd = 0;
    autofree u8 *buff = NULL;
    size_t countsize = ALIGN_ULONG(pidmem->count);
    ssize_t rwsize;
    off_t off;
    int ret;

    snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pidmem->pid);
    fd = open(mempath, O_RDWR);
    LOG_COND_CHECK((fd < 0), fd, failed);

    off = lseek(fd, pidmem->vaddr, SEEK_SET);
    LOG_COND_CHECK((off == -1), -1, failed);

    if (pidmem->flags == PROCMEM_READ) {
        buff = malloc(countsize);
        LOG_COND_CHECK((buff == NULL), -2, failed);

        rwsize = read(fd, buff, countsize);
        LOG_COND_CHECK((rwsize < 0), -1, failed);

        hex_mem(pidmem->vaddr, buff, (size_t)rwsize);
    }

    if (pidmem->flags == PROCMEM_WRITE) {
        rwsize = write(fd, (void *)&pidmem->value, sizeof(pidmem->value));
        LOG_COND_CHECK((rwsize < 0), -1, failed);
    }

failed:
    return ret;
}

int main(int argc, char *argv[])
{
    struct PIDMem pidmem = {0,0,0,0,0};
    int ret;

    parse_pidmem(argc, &argv[0], &pidmem);

    ret = check_pidmem(&pidmem);
    LOG_COND_CHECK((ret < 0), ret, failed);

    attach_pid(pidmem.pid);

    mem_rw(&pidmem);

failed:
    return ret;
}
