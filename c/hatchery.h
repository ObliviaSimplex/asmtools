
#ifndef hatchery_h__
#define hatchery_h__

#include <sys/user.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
//#include <sys/reg.h> // x86 specific - just contains symbolic names
//stored as #define clauses
#include <sys/types.h>


#ifdef __x86_64__

#define REGISTERS struct user_regs_struct

#endif // __x86_64__

#ifdef __arm__

#define REGISTERS struct user_regs

#endif // __arm__


int hatch_code (unsigned char *code, unsigned char *res);

int size_of_registers(void);

#define SYSREG_COUNT 7
#define SYSREG_BYTES 7*8

#define THE_SHELLCODE_LIES_BELOW 0x700000000000

int size_of_sysreg_union(void);

typedef union syscall_reg_vec {
unsigned long int rvec[SYSREG_COUNT]; // rax, rdi, rsi, rdx, r10, r8, r9
unsigned char bvec[SYSREG_BYTES];
} SYSCALL_REG_VEC;

enum sysreg_t {rax, rdi, rsi, rdx, r10, r8, r9};

  

#endif // hatchery_h__
