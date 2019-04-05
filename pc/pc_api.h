#ifndef __PC_API_H__
#define __PC_API_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>

#define PC_SYSCALL 378
#define PC_READ 379
#define PC_WRITE 380
#define PC_PREAD 381
#define PC_PWRITE 382
#define PC_READV 383
#define PC_WRITEV 384
#define PC_PREADV 385
#define PC_PWRITEV 386

/**
 * user-level PC collection API.
 * this only works on current desktop, which is patched to have system call number 378
 * for PC collection.
 * this stores PC information and the sum of PCs on separate file(/tmp/pc_syscall.log),
 * and returns the sum of pc.
 */
#define get_pc() syscall(PC_SYSCALL)

/**
 * I/O system calls with PC signature.
 */
#define read_pc(fd, buf, len, pc_sig) syscall(PC_READ, fd, buf, len, pc_sig)
#define write_pc(fd, buf, len, pc_sig) syscall(PC_WRITE, fd, buf, len, pc_sig)
#define pread64_pc(fd, buf, count, offset, pc_sig) syscall(PC_PREAD, fd, buf, count, offset, pc_sig)
#define pwrite64_pc(fd, buf, count, offset, pc_sig) syscall(PC_PWRITE, fd, buf, count, offset, pc_sig)
#define readv_pc(fd, iov, iovcnt, pc_sig) syscall(PC_READV, fd, iov, iovcnt, pc_sig)
#define writev_pc(fd, iov, iovcnt, pc_sig) syscall(PC_WRITEV, fd, iov, iovcnt, pc_sig)
//#define preadv_pc(fd, iov, iovcnt, offset, pc_sig) syscall(PC_PREADV, fd, iov, iovcnt, offset, pc_sig)
//#define pwritev_pc() syscall(PC_PWRITEV, )

#ifdef __cplusplus
}
#endif

#endif
