// gcc -o test test.c
#include <unistd.h>
int main(){
   write(1,"hello\n",6);
}
