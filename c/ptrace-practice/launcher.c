#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <stdint.h>
// #include <sys/syscall.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t  u8;

u8 *sc = "\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05";


void print_registers(struct user_regs_struct regs){
  printf("RAX: %x\n"
         "RBX: %x\n"
         "RCX: %x\n"
         "RDX: %x\n"
         "RSI: %x\n"
         "RDI: %x\n"
         ,regs.orig_rax
         ,regs.rbx
         ,regs.rcx
         ,regs.rdx
         ,regs.rsi
         ,regs.rdi
         ,regs.rip
         ,regs.eflags);
}



int code_call ( u8 *code, u64 *raxtrace ){
  // we'll start with some basic shellcode-testing
  // boilerplate. 
  long (*ret)() = (long(*)())code;

  int status;

  pid_t pid;
  pid = fork();
  
  if (pid == 0){ // if in child process (tracee)

    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    ret(32,64);
    kill(getpid(), SIGSTOP);
    exit(1);
    
  } else {      // if in parent process (tracer)
    
    int status;
    /* union u { */
    /*   u64 val; */
    /*   u8 bytes[sizeof(u64)]; */
    /* }data; */
    struct user_regs_struct regs;
    int start = 1;
    long ins;
    //    while(1){
      
      wait(&status);
      
      //ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
           
      /* Now for the actual tracing */
     
         
      ptrace(PTRACE_GETREGS, pid, NULL, &regs);
      print_registers(regs);
      
      /* if (start == 1) { */
      /*   ins = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, NULL); */
      /*   printf("\nRIP: %lx Instruction executed: %lx\n", */
      /*          regs.rip, ins); */
      /* } */
      
      
      if (WTERMSIG(status) == SIGSEGV){
        fprintf(stderr, "-- SEGFAULT --\n"); // not detecting it
        //  break;
      }
      /* If the child has exited cleanly or been killed
       * then break out of the loop and exit.
       */
      if (WIFEXITED(status) || WIFSIGNALED(status)){
        fprintf(stderr, "Child exited with status %d\n", status);
        //break;
      }
      
      // }
    
    
  }
  return status;
          
}

int add2(int a, int b){
  return a + b;
}

/* main() is just for testing purposes. */
int main(int argc, char **argv){
  //printf("sizeof(long) = %d\n", sizeof(long));
  unsigned char input[] =

    "\x55"         // push %rbp
    "\x48\x89\xe5" // mov %rsp,%rbp
    "\x89\x7d\xfc" // mov %edi, -0x4(%rbp)
    "\x89\x75\xf8" // mov %esi, -0x8(%rbp)
    "\x8b\x55\xfc" // mov -0x4(%rbp), %edx
    "\x8b\x45\xf8" // mov -0x8(%rbp), %eax
    "\x01\xd0"     // add %edx, %eax
    "\x5d"         // pop %rbp
    "\xc3";        // retq  // comment out for easy segfault
  int result = 0;
  //  scanf("%s", input);
  u64 *raxtrace = calloc(0x100,sizeof(u64));
  
  result = code_call(sc, raxtrace);
  printf("You're back. Exit status = %d.\n",result);
  return 0;
}
