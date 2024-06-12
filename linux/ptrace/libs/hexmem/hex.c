#include <stdio.h>
#include "logging.h"
#include "ctype.h"
#include "autofree.h"
#include "hex.h"
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define POUT_SIZE 4096

int write_file(const char *fname, void *inbuf, size_t inbuf_length)
{
    int ret;
    ssize_t count;
    int fd;

    fd = open(fname, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        printf("can't open %s file\n", fname);
        return -1;
    }

    count = write(fd, inbuf, inbuf_length);

    ret = count;

//clean:
    if (fd > 0) close(fd);
//exit:
    return ret;
}


static char * hex_str(const u8 *hex, int size)
{
    static char str[19];
    int index;

    str[0]  = '|';
    str[17] = '|';
    str[18] = '\0';

    for (index = 0; index < 16; index++) {
        str[index+1] = '.';
    }

    for (index = 0; index < size; index++) {
        if (hex[index] >= 0x21 && hex[index] <= 0x7e)
            str[index+1] = hex[index];
    }

    return &str[0];
}

int hex_mem(size_t addr, const u8 *buff, size_t size)
{
    autofree char *tmpbuff = NULL;
    char *outstart = NULL;
    char *outend = NULL;
    size_t index = 0;
    size_t padding = 0;
    int ret = 0;

    tmpbuff = malloc(POUT_SIZE);
    LOG_COND_CHECK((tmpbuff == NULL), -1, err_nomem);

    outstart = tmpbuff;
    outend = outstart + POUT_SIZE;

    for (index = 0; index < size || padding != 0; index++) {
        int count = 0;
        const char *formatarr[16] =  {
                                        [0x00] = "%p %02x", 
                                        [0x01 ... 0x07] = " %02x",
                                        [0x08] = "  %02x",
                                        [0x09 ... 0x0e] = " %02x",
                                        [0x0f] = " %02x  %s\n" 
                                     };

        const char *paddingattr[16]= {
                                        [0x00] = "%p %02x", 
                                        [0x01 ... 0x07] = "  %c",
                                        [0x08] = "   %c",
                                        [0x09 ... 0x0e] = "  %c",
                                        [0x0f] = "  %c  %s\n" 
                                     }; 
        u8 val = ' ';
        const char *format = paddingattr[index%16];

        if (padding == 0) {
            format = formatarr[index%16];
            val = buff[index];
        }

        switch(index%16) {
            case 0x0:
                count = snprintf(outstart, (size_t)(outend-outstart), format, (void *)(addr + index), val);
                break;
            case 0xf:
                {
                    char *str = hex_str(&buff[index&~(0x0f)], 16 - padding);
                    count = snprintf(outstart, (size_t)(outend-outstart), format, val, str);
                    padding = count >= (int)(outend-outstart) ? padding : 0;
                }
                break;
            default:
                count = snprintf(outstart, (size_t)(outend-outstart), format, val);
                break;
        }

        if (index + 1 == size && size % 16 != 0) {
            padding = index % 16;
        }

        if (count >= (int)(outend-outstart)) {
            *outstart = '\0';
            outstart = outend - POUT_SIZE;
            printf("%s", outstart);
            index--;
            continue;
        }

        outstart += count;
    }

    printf("%s", tmpbuff);

err_nomem:
    return ret;
}
