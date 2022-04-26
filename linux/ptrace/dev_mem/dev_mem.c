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

struct DevMem {
    int pid;
    size_t vaddr;
    size_t paddr;
    size_t count;
};

static void parse_devmem(int argc, char *argv[], struct DevMem *devmem)
{
    struct option opts[] = {
        {"pid",     required_argument,  0,  'p'},
        {"vaddr",   required_argument,  0,  'v'},
        {"count",   required_argument,  0,  'c'}
    };

    int arg = 0;
    int index = 0;

    while ((arg = getopt_long(argc, argv, "p:o:c:h", opts, &index)) != -1) {
        switch(arg) {
            case 'p':
                devmem->pid = atoi(optarg);
                break;
            case 'v':
                devmem->vaddr = strtoul(optarg, NULL, 0);
                break;
            case 'c':
                devmem->count = strtoul(optarg, NULL, 0);
                break;
            default: 
                break;
        }
    }
}

#define PAGE_SIZE 4096
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
    size_t vaddr = ALIGN_PAGE_DOWN(devmem->vaddr);
    size_t vpfn = vaddr/PAGE_SIZE;
    size_t pfn;
    off_t off;
    int ret;

    snprintf(path, sizeof(path), "/proc/%d/pagemap", devmem->pid);

    fd = open(path, O_RDONLY);
    LOG_COND_CHECK((fd < 0), fd, failed);

    off = lseek(fd, vpfn*8, SEEK_SET);

    ret = read(fd, (u8 *)&pfn, 8);
    LOG_COND_CHECK((ret != sizeof(pfn)), fd, failed);

    pfn = PFN(pfn);

    devmem->paddr = pfn * PAGE_SIZE;

failed:
    return ret;
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

static int get_pmem(struct DevMem *devmem)
{
    char path[16] = "/dev/mem";
    autoclose int fd;
    autofree u8 *buff;
    off_t off;
    ssize_t readsize;
    size_t count = ALIGN_PAGE_UP(devmem->count);
    int ret;

    fd = open(path, O_RDONLY);
    LOG_COND_CHECK((fd < 0), fd, failed);

    off = lseek(fd, devmem->paddr, SEEK_SET);
    LOG_COND_CHECK((off == -1), -1, failed);

    buff = malloc(count);
    LOG_COND_CHECK((buff == NULL), -1, failed);

    readsize = read(fd, buff, count);
    LOG_COND_CHECK((readsize < 0), -1, failed);

    hex_mem(ALIGN_PAGE_DOWN(devmem->vaddr), buff, (size_t)readsize);

failed:
    return ret;
}

int main(int argc, char *argv[])
{
    struct DevMem devmem;

    parse_devmem(argc, argv, &devmem);

    get_paddr(&devmem);
    get_pmem(&devmem);
}