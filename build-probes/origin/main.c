#include <stdio.h>
extern int f(void);
int main(void) { int r = f(); printf("f() = %d\n", r); return r == 42 ? 0 : 1; }
