#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int a = 0x33775566;

void func()
{
	if (a > 0) {
		printf("I'am OK\n");
		sleep(3);
	} else {
		printf("I've been attacked, i will die\n");
		exit(0);
	}

}

int main(int argc, char *argv[])
{	
	while(1) {
		func();
	}
}
