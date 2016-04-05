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
#include "example.h"


unsigned char *sc = "\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05";


void print_registers(unsigned char *bytes){
  #ifdef __x86_64__
  SYSCALL_REG_VEC srv;
  memcpy(srv.bvec, bytes, sizeof(SYSCALL_REG_VEC));
  printf("RAX: %llx\n"
         "RDI: %llx\n"
         "RSI: %llx\n"
         "RDX: %llx\n"
         "R10: %llx\n"
         "R8:  %llx\n"
         "R9:  %llx\n"
         ,srv.rvec[rax]
         ,srv.rvec[rdi]
         ,srv.rvec[rsi]
         ,srv.rvec[rdx]
         ,srv.rvec[r10]
         ,srv.rvec[r8]
         ,srv.rvec[r9]);
#endif //__x86_64__
  #ifdef __arm__
  int i;
  for (i = 0; i < 18; i++){
    printf("R%d: %lx\n", i, regs->uregs[i]);
  }
#endif // __arm__
}


int test_code(){
  void (*proc)() = (void(*)())example_bin;
  proc();
  return 1;
}


/* main() is just for testing purposes. */
int main(int argc, char **argv){
  int i=0;
  int result;
  test_code();
  //  scanf("%s", input);
  //REGISTERS *registers;
  //printf("size of registers struct: %d bytes\n", size_of_registers());
  //  registers = calloc(1,sizeof(REGISTERS));
  unsigned char *res;
  res = calloc(sizeof(SYSCALL_REG_VEC),1);
  puts("--- REGISTERS BEFORE ---");
  print_registers(res);
  result = hatch_code(example_bin,res);
  printf("You're back. Result code: %llx\n", result);
  puts("--- REGISTERS AFTER ---");
  print_registers(res);
  return 0;
}
