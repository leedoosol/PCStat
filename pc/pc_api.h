#ifndef __PC_API_H__
#define __PC_API_H__

#include <unistd.h>

#define PC_SYSCALL 378

/**
 * user-level PC collection API.
 * this only works on current desktop, which is patched to have system call number 378
 * for PC collection.
 * this stores PC information and the sum of PCs on separate file(/tmp/pc_syscall.log),
 * and returns the sum of pc.
 */
#define get_pc() syscall(PC_SYSCALL)

#endif
