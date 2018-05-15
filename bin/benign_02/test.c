// gcc -o test test.c -fPIE -pie
#include <unistd.h>
int main(){
   write(1,"hello\n",6);
}
