void main(){

  __asm__("jmp forward\n"
       "backward:\n"
          "pop    %rsi\n" //   # get the address of hello world string
          "movq   $4, %rax\n"//  # do write syscall
          "movq   $2, %rbx\n"//
          "movq   %rsi, %rcx\n"//
          "movq   $12, %rdx\n"//
          "int    $0x80\n"//
          "int3\n"//          # breakpoint. here the programme will 
          //        # stop and give control back to the parent
          //
          "forward: \n"//
          "call   backward\n"
          ".string \"Hello World\\n\"\n");
}
