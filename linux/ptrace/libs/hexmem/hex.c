#include <stdio.h>
#include "logging.h"
#include "ctype.h"
#include "autofree.h"
#include "hex.h"

#define POUT_SIZE 4096

static char * hex_str(const u8 hex[16])
{
    static char str[19];
    int index;

    str[0]  = '|';
    str[17] = '|';
    str[18] = '\0';

    for (index = 0; index < 16; index++) {
        if (hex[index] >= 0x21 && hex[index] <= 0x7e) {
            str[index+1] = hex[index];
            continue;
        }
        str[index+1] = '.';
    }

    return &str[0];
}

int hex_mem(size_t addr, const u8 *buff, size_t size)
{
    autofree char *tmpbuff = NULL;
    char *outstart = NULL;
    char *outend = NULL;
    size_t index = 0;
    int ret = 0;

    tmpbuff = malloc(POUT_SIZE);
    LOG_COND_CHECK((tmpbuff == NULL), -1, err_nomem);

    outstart = tmpbuff;
    outend = outstart + POUT_SIZE;

    for (index = 0; index < size; index++) {
        int count = 0;
        switch(index%16) {
            case 0x0:
                count = snprintf(outstart, (size_t)(outend-outstart), "%p %02x", (void *)(addr + index), buff[index]);
                break;
            case 0x8:
                count = snprintf(outstart, (size_t)(outend-outstart), "  %02x", buff[index]);
                break;
            case 0xf:
                {
                    char *str;
                    str = hex_str(&buff[index&~(0x0f)]);
                    count = snprintf(outstart, (size_t)(outend-outstart), " %02x  %s\n", buff[index], str);
                }
                break;
            default:
                count = snprintf(outstart, (size_t)(outend-outstart), " %02x", buff[index]);
                break;
        }
        
        if (count >= (size_t)(outend-outstart)) {
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