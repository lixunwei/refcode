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
#include "common.h"
#include "ctype.h"
#include "hex.h"

#define DEVMEM_READ         (0 << 1) 
#define DEVMEM_WRITE        (1 << 1)
#define DEVMEM_TRANSLATE    (2 << 1)
#define DEVMEM_PHYMODE      (3 << 1)
#define DEVMEM_VIRMODE      (4 << 1)

struct DevMem {
    int pid;
    size_t vaddr;
    size_t paddr;
    size_t count;
    size_t value;
    int flags;
};

static const char *help = 
"Usage: dev_mem <--pid pid> <--vaddr vaddr> <--count N>\n"
"\t-p, --pid pid\t\tThe pid of the process to be whatched\n"
"\t-v, --vaddr vaddr\tThe begin virutal address we want to access.\n"
"\t-y, --paddr paddr\tThe begin physical address we want to access.\n"
"\t-c, --count N\t\tRead only N count memeory.\n"
"\t-w, --write Val\t\tWrite Val to memeory.\n"
"\t-t, --translate Val\t\tTranslate a vritual address to physical address.\n";

static int check_devmem(struct DevMem *devmem)
{

    int ret = 0;
    int read = devmem->flags != DEVMEM_WRITE;

    LOG_COND_CHECK((devmem->pid == 0), -1, Help);

    if (devmem->flags & DEVMEM_READ)
        LOG_COND_CHECK((devmem->count == 0), -1, Help);


    return ret;

Help:
    printf("Invalid input argument\n");
    printf("%s", help);
    return ret;
}

static void parse_devmem(int argc, char *argv[], struct DevMem *devmem)
{
    struct option opts[] = {
        {"pid",         required_argument,  0,  'p'},
        {"vaddr",       required_argument,  0,  'v'},
        {"paddr",       required_argument,  0,  'y'},
        {"count",       required_argument,  0,  'c'},
        {"write",       required_argument,  0,  'w'},
        {"translate",   no_argument,        0,  't'},
        {"help",        no_argument,        0,  'h'},
    };

    int arg = 0; int index = 0;

    while ((arg = getopt_long(argc, argv, "p:o:c:w:h", opts, &index)) != -1) {
        switch(arg) {
            case 'p':
                devmem->pid = atoi(optarg);
                break;
            case 'v':
                devmem->vaddr = strtoul(optarg, NULL, 0);
                devmem->flags = DEVMEM_VIRMODE;
                break;
            case 'y':
                devmem->paddr = strtoul(optarg, NULL, 0);
                devmem->flags = DEVMEM_PHYMODE;
                break;
            case 'c':
                devmem->count = strtoul(optarg, NULL, 0);
                break;
            case 'w':
                devmem->value = strtoul(optarg, NULL, 0);
                devmem->flags = DEVMEM_WRITE;
                break;
            case 't':
                devmem->flags = DEVMEM_TRANSLATE;
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

#define ALIGN_PAGE_DOWN(addr) (addr)&~(PAGE_SIZE-1)
#define ALIGN_PAGE_UP(addr) (addr+PAGE_SIZE-1)&~(PAGE_SIZE-1)

#define PAGEMAP  64
#define PFN_BITS 55
#define PAGE_BITS (size_t)(1 << (PAGEMAP - PFN_BITS))
#define PFN_MASK ~((PAGE_BITS - 1) << PFN_BITS)
#define PFN(pfn) (pfn) & PFN_MASK

static int get_paddr(struct DevMem *devmem)
{
    char path[128];
    autoclose int fd;
    size_t vaddr = ALIGN_ULONG(devmem->vaddr);
    size_t vpfn = vaddr/PAGE_SIZE;
    size_t pfn;
    off_t off;
    int ret;

    snprintf(path, sizeof(path), "/proc/%d/pagemap", devmem->pid);

    fd = open(path, O_RDONLY);
    LOG_COND_CHECK((fd < 0), fd, failed);

    off = lseek(fd, vpfn*8, SEEK_SET);
    LOG_COND_CHECK((off == -1), -1, failed);

    ret = read(fd, (u8 *)&pfn, 8);
    LOG_COND_CHECK((ret != sizeof(pfn)), fd, failed);

    devmem->paddr = pfn * PAGE_SIZE + vaddr % PAGE_SIZE;

failed:
    return ret;
}

static int pmem_rw(struct DevMem *devmem)
{
    char path[16] = "/dev/mem";
    autoclose int fd;
    autofree u8 *buff = NULL;
    off_t off;
    ssize_t rwsize;
    size_t count = ALIGN_ULONG(devmem->count);
    int ret;

    fd = open(path, O_RDWR);
    LOG_COND_CHECK((fd < 0), fd, failed);

    off = lseek(fd, devmem->paddr, SEEK_SET);
    LOG_COND_CHECK((off == -1), -1, failed);

    if (devmem->flags == DEVMEM_READ) {
        buff = malloc(count);
        LOG_COND_CHECK((buff == NULL), -1, failed);

        rwsize = read(fd, buff, count);
        LOG_COND_CHECK((rwsize < 0), -1, failed);

        hex_mem(ALIGN_PAGE_DOWN(devmem->vaddr), buff, (size_t)rwsize);
    }

    if (devmem->flags == DEVMEM_WRITE) {
        rwsize = write(fd, (void *)&devmem->value, sizeof(devmem->value));
        LOG_COND_CHECK((rwsize != sizeof(devmem->value)), -1, failed);
    }

failed:
    return ret;
}

static void pmem_trans(struct DevMem *devmem)
{
   printf("%p\n", (void *)devmem->paddr); 
}

int main(int argc, char *argv[])
{
    struct DevMem devmem={0,0,0,0,0,0};
    int ret;

    parse_devmem(argc, argv, &devmem);
    ret = check_devmem(&devmem);
    LOG_COND_CHECK((ret < 0), -1, failed);

    get_paddr(&devmem);

    if (devmem.flags == DEVMEM_TRANSLATE)
        pmem_trans(&devmem);

    if (devmem.flags == DEVMEM_READ || devmem.flags == DEVMEM_WRITE)
        pmem_rw(&devmem);
    
failed:
    return ret;
}
