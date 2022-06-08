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

struct PIDMem {
    int pid;
    size_t vaddr;
    size_t count;
};

static const char *help = 
"Usage: proc_mem <--pid pid> <--vaddr vaddr> <--count N>\n"
"\t-p, --pid pid\t\tThe pid of the process to be whatched\n"
"\t-v, --vaddr vaddr\tThe begin virutal address we want to access.\n"
"\t-c, --count N\t\tRead only N count memeory.\n";

static int check_pidmem(struct PIDMem *pidmem)
{
    if (pidmem->pid == 0 || pidmem->count == 0 || pidmem->vaddr == 0) {
        printf("Invalid input argument\n");
        printf("%s",help);
        return -1;
    }
    
    return 0;
}

static void parse_pidmem(int argc, char *argv[], struct PIDMem *pidmem)
{
    struct option opts[] = {
        {"pid",     required_argument,  0,  'p'},
        {"vaddr",  required_argument,  0,   'v'},
        {"count",   required_argument,  0,  'c'},
        {"help",    no_argument,        0,  'h'}
    };

    int arg = 0;
    int index = 0;

    while ((arg = getopt_long(argc, argv, "p:v:c:h", opts, &index)) != -1) {
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

static int dump_mem(struct PIDMem *pidmem)
{
    char mempath[256];
    autoclose int fd;
    autofree u8 *buff;
    size_t countsize = ALIGN_ULONG(pidmem->count);
    ssize_t readsize;
    off_t off;
    int ret;

    snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pidmem->pid);
    fd = open(mempath, O_RDONLY);
    LOG_COND_CHECK((fd < 0), fd, failed);

    off = lseek(fd, pidmem->vaddr, SEEK_SET);
    LOG_COND_CHECK((off == -1), -1, failed);

    buff = malloc(countsize);
    LOG_COND_CHECK((buff == NULL), -2, failed);

    readsize = read(fd, buff, countsize);
    LOG_COND_CHECK((readsize < 0), -1, failed);

    hex_mem(pidmem->vaddr, buff, (size_t)readsize);

failed:
    return ret;
}

int main(int argc, char *argv[])
{
    struct PIDMem pidmem = {0,0,0};
    int ret;

    parse_pidmem(argc, &argv[0], &pidmem);

    ret = check_pidmem(&pidmem);
    LOG_COND_CHECK((ret < 0), ret, failed);

    attach_pid(pidmem.pid);
    dump_mem(&pidmem);

failed:
    return ret;
}
