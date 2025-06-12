#include <stdio.h>

int main() {
  int mem = 0x12345678;
  register long rax asm("rax") = 0x1234567812345678;
  register int edi asm("edi") = 0x77777777;
  asm("cmpxchg %[edi],%[mem]"
      : [ mem ] "+m"(mem), [ rax ] "+r"(rax)
      : [ edi ] "r"(edi));
  long rax2 = rax;
  printf("rax2 = %lx\n", rax2);
}

