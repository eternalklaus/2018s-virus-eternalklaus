// gcc -o test test.c -fPIC -pic
#include <unistd.h>
int main(){
   write(1,"hello\n",6);
}
