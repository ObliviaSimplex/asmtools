#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
//#include <sys/reg.h> // x86 specific - just contains symbolic names
//stored as #define clauses
#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#include "hatchery.h"
// todo: intercept syscalls, intercept segfaults

int size_of_registers(){
  return sizeof(REGISTERS);
}

int size_of_sysreg_union(){
  return SYSREG_BYTES;
}

int hatch_code (unsigned char *code, unsigned char *res){
  /* cast the byte array as a function */
  long (*proc)() = (long(*)())code;
  SYSCALL_REG_VEC syscall_reg_vec;
  /* This struct will be loaded by the tracer with a representation
   * of all the registers at the end of the code's execution. 
   */
  // struct user_regs_struct
  
  pid_t pid;
  /* fork a new process in which to run the shellcode */
  pid = fork();
  if (pid == 0){ // if in child process (tracee)
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    kill(getpid(), SIGSTOP); // to let the tracer catch up
    proc(); // if you want to pass any params to the code, do it here
    kill(getpid(), SIGSTOP); // to let the tracer catch up
    exit(1); // we're done with this child, now
  } else {
    /* We're in the tracer process. It will observe the child and
     * report back to the head office.
     */
    REGISTERS *regs;
    regs = calloc(1,sizeof(REGISTERS));

    int status;
    wait(&status);
    printf("-- TRAPPED CHILD %d WITH STATUS %d --\n", pid, status);
    long int inst = 0;
    int in_code = 0;
    while(!WIFEXITED(status)){

      int ptrace_errno;
      if ((ptrace_errno = ptrace(PTRACE_GETREGS, pid, NULL, regs)) == -1){
        fprintf(stderr, "-- ERROR GETTING REGISTERS; ERROR CODE %d --\n", ptrace_errno);
        //      exit(EXIT_FAILURE);
      }
      //    print_registers(regs);
      if (WTERMSIG(status) == SIGSEGV){
        fprintf(stderr, "-- SEGFAULT --\n");  // not detecting ?
      }

      inst = regs->rip;
      if (in_code && inst > THE_SHELLCODE_LIES_BELOW)
        break;
      
      in_code = inst < THE_SHELLCODE_LIES_BELOW;

      if (in_code){        
        printf("AT INSTRUCTION %llx\n", inst);
        printf("IN RAX: %llx\n" 
               "IN RDI: %llx\n"
               "IN RSI: %llx\n"
               "IN RDX: %llx\n"
               "IN R10: %llx\n"
               "IN R8:  %llx\n"
               "IN R9:  %llx\n\n",
               regs->rax,
               regs->rdi,
               regs->rsi,
               regs->rdx,
               regs->r10,
               regs->r8,
               regs->r9);
        
        
        /**
         * Serialize the register information
         **/
        syscall_reg_vec.rvec[rax] = regs->rax;
        syscall_reg_vec.rvec[rdi] = regs->rdi;
        syscall_reg_vec.rvec[rsi] = regs->rsi;
        syscall_reg_vec.rvec[rdx] = regs->rdx;
        syscall_reg_vec.rvec[r10] = regs->r10;
        syscall_reg_vec.rvec[r8] = regs->r8;
        syscall_reg_vec.rvec[r9] = regs->r9;
        
      }
      
      ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

      waitpid(pid, &status, 0);
            
           
    }
    memcpy(res, syscall_reg_vec.bvec, SYSREG_BYTES);
    free(regs);
  }
  
  return syscall_reg_vec.rvec[rax];
}

/**
   ideas:
   screen out jump instructions from gadgets, for now. 
   end each gadget with a null/dummy syscall, to hand
   control to the monitor
*/

