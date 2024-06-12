#ifndef __HEX_H
#define __HEX_H

int hex_mem(size_t addr, const u8 *buff, size_t size);
int write_file(const char *fname, void *inbuf, size_t inbuf_length);

#endif
