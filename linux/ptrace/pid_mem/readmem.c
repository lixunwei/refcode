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

struct PIDMem {
    int pid;
    size_t offset;
    size_t count;
};

static int check_pidmem(struct PIDMem *pidmem)
{
    if (pidmem->pid == 0 || pidmem->count == 0) {
        printf("Invalid input argument\n");
        return -1;
    }
    
    return 0;
}

static void parse_pidmem(int argc, char *argv[], struct PIDMem *pidmem)
{
    struct option opts[] = {
        {"pid",     required_argument,  0,  'p'},
        {"offset",  required_argument,  0,  'o'},
        {"count",   required_argument,  0,  'c'}
    };

    int arg = 0;
    int index = 0;

    while ((arg = getopt_long(argc, argv, "p:o:c:h", opts, &index)) != -1) {
        switch(arg) {
            case 'p':
                pidmem->pid = atoi(optarg);
                break;
            case 'o':
                pidmem->offset = strtoul(optarg, NULL, 0);
                break;
            case 'c':
                pidmem->count = strtoul(optarg, NULL, 0);
                break;
            default: 
                break;
        }
    }
}

static int attach_pid(int pid)
{
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    waitpid(pid, NULL, 0);//wait for the attach to succeed.
}

static void hex_mem(size_t addr, const u8 *buff, size_t size)
{
    size_t index = addr;
    const u8 *p = buff;

    for (; (size_t)p+16 <= (size_t)buff+size; ) {
        printf("%p  %02x %02x %02x %02x",(void *)index, p[0],p[1],p[2],p[3]); p += 4;
        printf(" %02x %02x %02x %02x",p[0],p[1],p[2],p[3]); p += 4;
        printf("  %02x %02x %02x %02x",p[0],p[1],p[2],p[3]); p += 4;
        printf(" %02x %02x %02x %02x\n",p[0],p[1],p[2],p[3]);p += 4;
        index += 16;
    }
}

#define PAGE_SIZE 4096
#define ALIGN_PAGE(addr) ((addr)+PAGE_SIZE-1)&~(PAGE_SIZE-1)

static int dump_mem(struct PIDMem *pidmem)
{
    char mempath[256];
    autoclose int fd;
    autofree u8 *buff;
    size_t countsize = ALIGN_PAGE(pidmem->count);
    ssize_t readsize;
    off_t off;
    int ret;

    snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pidmem->pid);
    fd = open(mempath, O_RDONLY);
    LOG_COND_CHECK((fd < 0), fd, failed);

    off = lseek(fd, pidmem->offset, SEEK_SET);
    LOG_COND_CHECK((off == -1), -1, failed);

    buff = malloc(countsize);
    LOG_COND_CHECK((buff == NULL), -2, failed);

    readsize = read(fd, buff, countsize);
    LOG_COND_CHECK((readsize < 0), -1, failed);

    hex_mem(pidmem->offset, buff, (size_t)readsize);

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