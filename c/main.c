#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#ifdef __x86_64__
#include <sys/reg.h>
#endif


#include "hatchery.h"


unsigned char *sc = "\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05";


void print_registers(REGISTERS regs){
  #ifdef __x86_64__
  printf("RAX: %llx\n"
         "RBX: %llx\n"
         "RCX: %llx\n"
         "RDX: %llx\n"
         "RSI: %llx\n"
         "RDI: %llx\n"
         "RIP: %llx\n"
         "EFLAGS: %x\n"
         ,regs.rax
         ,regs.rbx
         ,regs.rcx
         ,regs.rdx
         ,regs.rsi
         ,regs.rdi
         ,regs.rip
         ,regs.eflags);
#endif //__x86_64__
  #ifdef __arm__
  int i;
  for (i = 0; i < 18; i++){
    printf("R%d: %lx\n", i, regs.uregs[i]);
  }
#endif // __arm__
}


/* main() is just for testing purposes. */
int main(int argc, char **argv){
  //printf("sizeof(long) = %d\n", sizeof(long));
  unsigned char input[0x1000] =

    "\x55"// push %rbp
    "\x48\x89\xe5" // mov %rsp,%rbp
    "\x89\x7d\xfc" // mov %edi, -0x4(%rbp)
    "\x89\x75\xf8" // mov %esi, -0x8(%rbp)
    "\x8b\x55\xfc" // mov -0x4(%rbp), %edx
    "\x8b\x45\xf8" // mov -0x8(%rbp), %eax
    "\x01\xd0"     // add %edx, %eax
    "\x5d"         // pop %rbp
    "\xc3";        // retq  // comment out for easy segfault
  unsigned char *result;
  //  scanf("%s", input);

  result = hatch_code(input);
  printf("You're back.\n");
  REGISTERS registers;
  memcpy(&registers, result, sizeof(registers));
  free(result);
  print_registers(registers);
  return 0;
}
