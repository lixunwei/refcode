#include <elf.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/procfs.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <sys/sendfile.h>

#define __align__(n,a) ((n + a - 1) & ~((typeof(n))(a - 1)))
#define align4(n) __align__(n, 4)

/* An ELF note in memory */
typedef struct eslfnote
{
    Elf64_Nhdr nhdr;
    char *name;
    void *data;
    size_t data_size;
}elfnode_t;

typedef struct vma {
    uintptr_t start;
    uintptr_t end;
    bool perm[4];
}vma_t;

typedef struct mapping_data {
    uintptr_t vm_start;
    uintptr_t vm_end;
    uint64_t off;
    bool perms[4];//rwxp
    char filename[256];
}mapping_t;

typedef struct {
    Elf64_Ehdr ehdr;
    elfnode_t *nodes;
    uint32_t node_count;
    uint32_t node_index;
    size_t node_size;
    vma_t *vmas;
    uint32_t vma_count;
    uint32_t vma_index;
    mapping_t *mappings;
    uint32_t map_index;
    uint32_t map_count;
}coredump_t;

coredump_t coredump = {
    .ehdr = {
        .e_ident = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE, 0x00, 0x00},
        .e_type = ET_CORE,
        .e_machine = EM_X86_64,
        .e_version = EV_CURRENT,
        .e_entry = 0x00,
        .e_phoff = sizeof(Elf64_Ehdr),
        .e_shoff = 0,
        .e_flags = 0,
        .e_ehsize = sizeof(Elf64_Ehdr),
        .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum = 1,
        .e_shentsize = sizeof(Elf64_Shdr),
        .e_shnum = 0,
        .e_shstrndx = 0,    
    },
    .node_index = 0,
    .vma_index = 0,
    .node_size = 0,
};

int alloc_coredump(coredump_t *core)
{
    core->node_count = 64;
    core->nodes = calloc(sizeof(elfnode_t), core->node_count);
    core->map_count = 128;
    core->mappings = calloc(sizeof(mapping_t), core->map_count);
}

static int parser_mapping(pid_t pid)
{
    char mpath[128] = {0};
    FILE *stream = NULL;
    char *line = NULL;
    size_t len = 0;
    uint32_t count = 0;

    snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);

    stream = fopen(mpath, "r");
    if (stream == NULL) {
        perror("fopen");
        exit(1);
    }

    while(getline(&line, &len, stream) != -1) {
        char r,w,x,p;
        mapping_t *map = &coredump.mappings[coredump.map_index];

        sscanf(line, "%lx-%lx %c%c%c%c %lx %*s %*s %256s", 
            &map->vm_start,
            &map->vm_end,
            &r,&w,&x,&p,
            &map->off,
            map->filename);
      
        map->perms[0] = (r != '-') ? true : false;
        map->perms[1] = (w != '-') ? true : false;
        map->perms[2] = (x != '-') ? true : false;
        map->perms[3] = (p != '-') ? true : false;

        if (!map->perms[0] && !map->perms[1])
            continue;
        
        if (!strcmp(map->filename, "[vvar]")) continue;
        if (!strcmp(map->filename, "[vdso]")) continue;

        coredump.map_index++;
    }

    return 0;
}

static void attach_pid(int pid)
{
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    waitpid(pid, NULL, 0);//wait for the attach to succeed.
}

/*
 *   +-------------------------+
 *   | ELF Header             |
 *   +-------------------------+
 *   | Program Header Table   |
 *   +-------------------------+
 *   | .text Section          |
 *   +-------------------------+
 *   | .rodata Section        |
 *   +-------------------------+
 *   | .data Section          |
 *   +-------------------------+
 *   | .bss Section           |
 *   +-------------------------+
 *   | Other Section (debug)  |
 *   +-------------------------+
 *   | Section Header Table   |
 *   +-------------------------+
 */
static void fill_node(coredump_t *coredump, uint32_t type, void *data, size_t datasize)
{
    void *p = NULL;
    if (coredump->node_index >= coredump->node_count) {
        coredump->node_count += 32;
        coredump->nodes = realloc(coredump->nodes, sizeof(elfnode_t) * coredump->node_count);
    }

    elfnode_t *node = &coredump->nodes[coredump->node_index++];
    node->name = "CORE",
    node->nhdr.n_namesz = strlen(node->name) + 1;
    node->nhdr.n_type = type;
    node->nhdr.n_descsz = datasize; 
    node->data_size = sizeof(node->nhdr) + align4(datasize) + align4(node->nhdr.n_namesz);
    node->data = calloc(node->data_size, 1);
    p = node->data;
    memcpy(p, (void *)&node->nhdr, sizeof(node->nhdr));
    p += sizeof(node->nhdr);
    memcpy(p, (void *)node->name, node->nhdr.n_namesz);
    p += align4(node->nhdr.n_namesz);
    memcpy(p, (void *)data, datasize);

    coredump->node_size += node->data_size;
}
static int fill_psinfo(void)
{
    prpsinfo_t psinfo = {
        .pr_state = 0,
        .pr_sname = 'R',
        .pr_zomb = 0,
        .pr_nice = 20,
        .pr_flag = 0x0000000040400000,
        .pr_uid = 1000,
        .pr_gid = 1000,
        .pr_pid = 1234,
        .pr_ppid = 244,
        .pr_pgrp = 11,
        .pr_sid = 22,
        .pr_fname = "kmsskit",
        .pr_psargs = "--help",
    };

    fill_node(&coredump, NT_PSINFO, &psinfo, sizeof(psinfo));

    return 0;
}
static int fill_prstatus(pid_t pid)
{
    int ret = 0;
    prstatus_t prstatus = {0}; 
    elf_fpregset_t fpreg = {0};
    siginfo_t sig = {0};
    DIR *dp = NULL;
    struct dirent *entry = NULL;
    char path[128];

    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    dp = opendir(path);

    while(((entry = readdir(dp)) != NULL)) {
        if (!isdigit(entry->d_name[0]))
            continue;
        pid_t tid = atoi(entry->d_name);

        prstatus.pr_pid = tid;
        if (tid != pid) {
            attach_pid(tid);
        }
        ret = ptrace(PTRACE_GETREGS, tid, NULL, &prstatus.pr_reg);
        if (ret < 0) {
            printf("get regs error : %s tid = %d\n", strerror(errno), tid);
        }

        ret = ptrace(PTRACE_GETFPREGS, tid, NULL, &fpreg);
        if (ret < 0) {
            printf("get fpregs error : %s tid = %d\n", strerror(errno), tid);
        }

        ret = ptrace(PTRACE_GETSIGINFO, tid, NULL, &sig);
        if (ret < 0) {
            printf("get siginfo error : %s tid = %d\n", strerror(errno), tid);
        }

        fill_node(&coredump, NT_PRSTATUS, &prstatus, sizeof(prstatus));
        fill_node(&coredump, NT_FPREGSET, &fpreg, sizeof(fpreg));
        fill_node(&coredump, NT_SIGINFO, &sig, sizeof(sig));
    }

    return 0;
}

static int fill_mapping(pid_t pid)
{
    uint64_t *data = NULL;
    uint64_t *pdata = NULL;
    char *pchar = NULL;

    parser_mapping(pid);

    data = calloc(4096, 1);
    data[0] = 0;
    data[1] = 1;
    pdata = data + 2;

    for (size_t i = 0; i < coredump.map_index; i++) {
        mapping_t *map = &coredump.mappings[i];
        if (map->filename[0] != '/')
            continue;
        *pdata++ = map->vm_start;
        *pdata++ = map->vm_end;
        *pdata++ = map->off;
        data[0]++;
    }

    size_t fn = 0;
    pchar = (char *)pdata;
    for (size_t i = 0; i < coredump.map_index; i++) {
        mapping_t *map = &coredump.mappings[i];
        if (map->filename[0] != '/')
            continue;
        fn = strlen(map->filename) + 1;
        memcpy(pchar, map->filename, fn);
        pchar += fn;
    }

    fill_node(&coredump, NT_FILE, (void *)data, (size_t)(pchar - (char *)data));

    free(data);
}
static int fill_auxv(pid_t pid)
{
    int ret = 0;
    char path[64];
    uint8_t auxv[1024];
    int fd = -1;

    snprintf(path, sizeof(path), "/proc/%d/auxv", pid);

    fd = open(path, O_RDONLY);
    ret = read(fd, &auxv, sizeof(auxv));
    close(fd);

    fill_node(&coredump, NT_AUXV, (void *)&auxv, ret);

    return 0;
}

static int emit_phdr(FILE *fstream)
{
    Elf64_Phdr phdr = {
        .p_type =  PT_NOTE,
        .p_flags = PF_R,
        .p_offset = 0,
        .p_vaddr = 0,
        .p_paddr = 0,
        .p_filesz = coredump.node_size,
        .p_memsz = 0,
        .p_align = 0x01,
    };

    phdr.p_offset = sizeof(Elf64_Ehdr) + sizeof(phdr) * (coredump.map_index + 1);
    fwrite((const void *)&phdr, sizeof(phdr), 1, fstream);

    phdr.p_type = PT_LOAD;
    for (size_t i = 0; i < coredump.map_index; i++) {
        mapping_t *map = &coredump.mappings[i];

        phdr.p_flags = 0;
        if (map->perms[0]) phdr.p_flags |= PF_R;
        if (map->perms[1]) phdr.p_flags |= PF_W;
        if (map->perms[2]) phdr.p_flags |= PF_X;
        phdr.p_offset += phdr.p_filesz;
        phdr.p_filesz = map->vm_end - map->vm_start;
        phdr.p_vaddr = map->vm_start;
        phdr.p_memsz = phdr.p_filesz;
        fwrite((const void *)&phdr, sizeof(phdr), 1, fstream);
        coredump.ehdr.e_phnum++;
    }
}

static ssize_t sync_sendfile(FILE *fstream, int sfd, off_t *off, size_t size)
{
    off_t offset;
    uint8_t *buff = NULL;
    ssize_t ret;

    offset = lseek(sfd, *off, SEEK_SET);
    if (offset < 0) {
        printf("lseek failed (%s)\n", strerror(errno));
        exit(1);
    }

    buff = malloc(size);
    if (buff == NULL) {
        printf("malloc failed (%s)\n", strerror(errno));
        exit(1);
    }

    ret = read(sfd, buff, size);
    if (ret < 0) {
        printf("read failed (%s)\n", strerror(errno));
        exit(1);
    }

    fwrite(buff, size, 1, fstream);
    free(buff);
}
static int load_pages(FILE *fstream, pid_t pid)
{
    int memfd = -1;
    char path[128];
    int ret = 0;
    off_t off = 0;
    ssize_t sret;

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    memfd = open(path, O_RDONLY);
    if (memfd < 0) {
        printf("open %s failed (%s)\n", path, strerror(errno));
        exit(1);
    }

    for (size_t i = 0; i < coredump.map_index; i++) {
        mapping_t *map = &coredump.mappings[i];

        sret = sync_sendfile(fstream, memfd, &map->vm_start, map->vm_end - map->vm_start);
        if (sret < 0) {
            printf("sendfile %s failed (%s)\n", path, strerror(errno));
            exit(1);
        }
    }

    close(memfd);

    return 0;
}
int main(int argc, char *argv[])
{
    int ret = 0;
    pid_t pid = atoi(argv[1]);
    FILE *fstream = fopen("./elf.bin", "w");

    attach_pid(pid);

    alloc_coredump(&coredump);

    fill_psinfo();
    fill_prstatus(pid);
    fill_auxv(pid);
    fill_mapping(pid);

    fwrite((const void *)&coredump.ehdr, sizeof(coredump.ehdr), 1, fstream);

    emit_phdr(fstream);

    for (size_t i = 0; i < coredump.node_index; i++) {
        fwrite((const void *)coredump.nodes[i].data, coredump.nodes[i].data_size, 1, fstream);
    }

    load_pages(fstream, pid);

    fseek(fstream, 0, SEEK_SET);
    fwrite((const void *)&coredump.ehdr, sizeof(coredump.ehdr), 1, fstream);
}