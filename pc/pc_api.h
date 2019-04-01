#ifndef __PC_API_H__
#define __PC_API_H__

#include <unistd.h>

#define PC_SYSCALL 378

#define get_pc() syscall(PC_SYSCALL)

#endif
