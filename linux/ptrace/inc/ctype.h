#ifndef __CTYPE_H
#define __CTYPE_H

#if __WORDSIZE == 64
typedef signed long int i64;
typedef unsigned long int u64;
#else
typedef signed long long int i64;
typedef unsigned long long int u64;
#endif

typedef signed char i8;
typedef unsigned char u8;

typedef signed short int i16;
typedef unsigned short int u16;

typedef signed int i32;
typedef unsigned int u32;

#endif