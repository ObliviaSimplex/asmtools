#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>   /* For user_regs_struct
                             etc. */

const int long_size = sizeof(long);

void getdata(pid_t child, long addr, char *str, int len){
  char *laddr;
  int i, j;
  union u{
    long val;
    char chars[long_size];
  }data;
  i = 0;
  j = len / long_size;
  laddr = str;

  while (i < j){
    data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
    memcpy(laddr, data.chars, long_size);
    ++i;
    laddr += long_size;
  }
  j = len % long_size;
  if (j != 0) {
    data.val = ptrace(PTRACE_PEEKDATA, child, addr +i * 8, NULL);
    memcpy(laddr, data.chars, j);
  }
  str[len] = '\0';
}

void putdata(pid_t child, long addr, char *str, int len){
  char *laddr;
  int i, j;
  union u {
    long val;
    char chars[long_size];
  }data;
  i = 0;
  j = len / long_size;
  laddr = str;
  while (i < j) {
    memcpy(data.chars, laddr, long_size);
    ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
    ++i;
    laddr += long_size;
  }
  j = len % long_size;
  if (j != 0){
    memcpy(data.chars, laddr, j);
    ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
  }
}

int main(int argc, char *argv[]){
  pid_t traced_process;
  struct user_regs_struct regs, newregs;
  long ins;
  /* int 0x80, int3 */
  //char code[] = {0xcd, 0x80, 0xcc, 0};
  //char backup[4];
  int len = 51;
  char insertcode[] =
    "\x55"
    "\x48\x89\xe5"
    "\xeb\x1c"
    "\x5e"
    "\x48\xc7\xc0\x04\x00\x00\x00"
    "\x48\xc7\xc3\x02\x00\x00\x00"
    "\x48\x89\xf1"
    "\x48\xc7\xc2\x0c\x00\x00\x00"
    "\xcd\x80"
    "\xcc"
    "\xe8\xdf\xff\xff\xff"
    "\x48"
    "\x65\x6c"
    "\x6c"
    "\x6f"
    "\x20\x57\x6f"
    "\x72\x6c"
    "\x64\x0a\x00"
    "\x90"
    "\x5d"
    "\xc3";

    /* "\xeb\x15\x5e\xb8\x04\x00" */
    /* "\x00\x00\xbb\x02\x00\x00\x00\x89\xf1\xba" */
    /* "\x0c\x00\x00\x00\xcd\x80\xcc\xe8\xe6\xff" */
    /* "\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f" */
    //"\x72\x6c\x64\x0a\x00";
  char backup[len];

  if(argc != 2){
    printf("Usage: %s <pid to be traced>\n",
           argv[0], argv[1]);
    exit(1);
  }
  traced_process = atoi(argv[1]);
  ptrace(PTRACE_ATTACH, traced_process, NULL, NULL);
  wait(NULL);
  ptrace(PTRACE_GETREGS, traced_process, NULL, &regs);
  /* copy instructions to a backup variable */
  getdata(traced_process, regs.rip, backup, len);
  /* put the breakpoint */
  putdata(traced_process, regs.rip, insertcode, len);
  /* let the process continue and execute the int 3 instruction */
  ptrace(PTRACE_CONT, traced_process, NULL, NULL);
  wait(NULL);
  printf("The process stopped, putting back "
         "the original instructions.\n");
  printf("Press <enter> to continue.\n");
  getchar();
  //  putdata(traced_process, regs.rip, backup, len);
  /* Setting the RIP back to the original instruction
     to let the process continue */
  //ptrace(PTRACE_SETREGS, traced_process, NULL, &regs);
  ptrace(PTRACE_DETACH, traced_process, NULL, NULL);
  return 0;
}
    
