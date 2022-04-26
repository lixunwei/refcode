#ifndef __LOGGING_H
#define __LOGGING_H

#include <string.h>
#include <errno.h>

#define LOG_COND_CHECK(cond, err, loc)\
do {\
	if ( cond ) {\
		fprintf(stderr, "[ERROR] func:%s line:%d [%s] ret = %d (%s)\n", __FUNCTION__, __LINE__, #cond, err, strerror(errno));\
		ret = err;\
		goto loc; \
	}\
}while(0)

#endif