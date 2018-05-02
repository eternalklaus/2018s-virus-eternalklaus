# eternal virus

This is a proof-of-concept virus written in class
[IS-521](https://github.com/KAIST-IS521/) at KAIST.

### Author

Jiwon Choi (eternalklaus)

### FIXME: describe your virus.

FIXME: currently this virus does not compile!

### Requirement
1. Infected binaries should run the same logic: it should infect other binary files.  
2. Virus should not destroy the file system: you do not remove files.
3. Virus should never remove existing files.
4. Program is malicious when it can propagate by infecting other binaries. --> 악성행위안해도 전파시키는것만으로도 malicious.
5. Virus should should not require any installation of dependent libraries.
6. 바이러스는 루트권한X 유저권한으로돌아간다
7. Does "without calling libc function" -> Makefile에서 -nolib옵션 수정하고 static으로 박아서 컴파일해라. 런타임에 립씨안부르도록?
