INCFILE=$(wildcard inc/*.h)
SRCFILE=$(wildcard *.c)

SRC_SYSCALL=$(wildcard syscall/*.c)
SRC_READMEM=$(wildcard pid_mem/*.c)
SRC_DEVMEM=$(wildcard dev_mem/*.c)

CFLAGS += "-I./inc"

all: syscall.bin readmem.bin devmem.bin

syscall.bin: $(SRC_SYSCALL) $(INCFILE)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

readmem.bin: $(SRC_READMEM) $(INCFILE)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

devmem.bin: $(SRC_DEVMEM) $(INCFILE)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

.PHONY : clean

clean : 
	@rm -f syscall.bin
	@rm -f readmem.bin
	@rm -f devmem.bin
