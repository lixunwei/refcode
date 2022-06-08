#ifndef __COMMON_H
#define __COMMON_H

#define PAGE_SIZE 4096
#define ALIGN_PAGE(addr) ((addr)+PAGE_SIZE-1)&~(PAGE_SIZE-1)

#define ULONG_SIZE sizeof(unsigned long)
#define ALIGN_ULONG(data) ((data)+ULONG_SIZE-1)&~(ULONG_SIZE-1)

#endif