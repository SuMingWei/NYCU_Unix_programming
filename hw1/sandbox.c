#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <elf.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define errquit(m)	{ perror(m); _exit(-1); }

long long getBaseAddress() {
	int fd, sz;
	char buf[16384];
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);

    char addr[16] = "";
    strncpy(addr, buf, 12); 

    return strtoll(addr, NULL, 16);
}

int myOpen(const char *pathname, int flags, mode_t mode){
    // printf("==my open==\n");
    char logger[1024];
    int loggerFd = atoi(getenv("LOGGER_FD"));

    
    FILE *f = fopen(getenv("SANDBOX_CONFIG"),"r");
    // FILE *f = fopen("config-example.txt","r");
    // FILE *f = fopen("config.txt","r");
    char buf[256];
    int ret = 0;


    char path[256];
    char line[256];
    realpath(pathname,path);

    bool start = false;
    while(!feof(f)){
        fgets(buf, 256, f);
        buf[strcspn(buf,"\r\n")] = '\0';
        // printf("%s\n",buf);
        if(strcmp(buf,"BEGIN open-blacklist") == 0){
            start = true;
            continue;
        }
        if(strcmp(buf,"END open-blacklist") == 0){
            ret = open(path, flags, mode);
            break;
        }
        if(start){
            realpath(buf, line);
            if(strcmp(line, path) == 0){
                errno = EACCES;
                ret = -1;
                break;
            }
        }
    }
    
    fclose(f);
    if(flags == O_CREAT || flags == O_TMPFILE){
        sprintf(logger, "[logger] open(\"%s\", %d, %d) = %d\n", path, flags, mode, ret);
    }else{
        sprintf(logger, "[logger] open(\"%s\", %d, 0) = %d\n", path, flags, ret);
    }
    write(loggerFd, logger, strlen(logger));
    
    return ret;
}

ssize_t myRead(int fd, void *buf, size_t count){
    // printf("==my read==\n");
    char logger[1024];
    int loggerFd = atoi(getenv("LOGGER_FD"));

    ssize_t ret = 0;
    pid_t pid = getpid();
    
    ret = read(fd,buf,count);
    char *bufString = (char *)buf;

    char fileName[256];
    sprintf(fileName, "%d-%d-read.log", pid, fd);
    FILE *logFile = fopen(fileName, "a+");
    // printf(fileName);

    // get content bytes
    fseek(logFile, 0L, SEEK_END);
    long numbytes = ftell(logFile);
    // reset file position indicator
    fseek(logFile, 0L, SEEK_SET);
    // read log content
    char *logContent;
    logContent = (char *)calloc(numbytes, sizeof(char));
    fread(logContent, sizeof(char), numbytes, logFile);
    // printf("===%s\n", logContent);

    char *entireContent;
    entireContent = (char *)calloc((numbytes + ret), sizeof(char));

    // printf("%s\n",buf);

    FILE *f = fopen(getenv("SANDBOX_CONFIG"),"r");
    // FILE *f = fopen("config-example.txt","r");
    // FILE *f = fopen("config.txt","r");
    char line[256];
    bool start = false;
    while(!feof(f)){
        fgets(line, 256, f);
        line[strcspn(line,"\r\n")] = '\0';
        // printf("%s\n",line);
        if(strcmp(line,"BEGIN read-blacklist") == 0){
            start = true;
            continue;
        }
        if(strcmp(line,"END read-blacklist") == 0){
            break;
        } 
        if(start){
            strncpy(entireContent, logContent,numbytes);
            strncpy(&entireContent[numbytes], bufString,ret);

            // printf("%s\n", entireContent);
            if(strstr(entireContent, line) != NULL){
                // printf("b\n");
                close(fd);
                fclose(f);
                fclose(logFile);
                errno = EIO;
                ret = -1;
                sprintf(logger, "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, ret);
                write(loggerFd, logger, strlen(logger));
                return ret;
            }
            // printf("aaa\n");
        }
    }
    fclose(f);
    
    // fprintf(logFile, "%s", (char *)buf);
    
    // printf("%s\n",bufString);
    // fwrite(bufString, sizeof(char), strlen(bufString), logFile);
    fwrite(buf, ret, 1, logFile);
    fclose(logFile);

    sprintf(logger, "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, ret);
    write(loggerFd, logger, strlen(logger));
    // printf("dsd\n");
    return ret;
}

ssize_t myWrite(int fd, void *buf, size_t count){
    // printf("==my write==\n");
    char logger[1024];
    int loggerFd = atoi(getenv("LOGGER_FD"));

    ssize_t ret = 0;
    pid_t pid = getpid();

    ret = write(fd,buf,count);
    
    char fileName[256];
    sprintf(fileName, "%d-%d-write.log", pid, fd);
    // printf(fileName);

    FILE *logFile = fopen(fileName, "a+");
    // fprintf(logFile, "%s", (char *)buf);
    // fwrite(buf, ret, 1, logFile);
    char *bufString = (char *)buf;
    // printf("%s\n",bufString);
    // fwrite(bufString, sizeof(char), strlen(bufString), logFile);
    fwrite(buf, ret, 1, logFile);
    fclose(logFile);


    sprintf(logger, "[logger] write(%d, %p, %ld) = %ld\n", fd, buf, count, ret);
    write(loggerFd, logger, strlen(logger));

    return ret;
}

int myConnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    char logger[1024];
    int loggerFd = atoi(getenv("LOGGER_FD"));

    int ret = 0;
    struct sockaddr_in *ip = (struct sockaddr_in *)(addr);
    char connectIp[64];
    strcpy(connectIp, inet_ntoa(ip->sin_addr));
    // printf("%s\n", connectIp);
    // ret = connect(sockfd, addr, addrlen);

    FILE *f = fopen(getenv("SANDBOX_CONFIG"),"r");
    // FILE *f = fopen("config-example.txt","r");
    // FILE *f = fopen("config.txt","r");
    char line[256];
    bool start = false;
    while(!feof(f)){
        fgets(line, 256, f);
        line[strcspn(line,"\r\n")] = '\0';
        // printf("%s\n",line);
        if(strcmp(line,"BEGIN connect-blacklist") == 0){
            start = true;
            continue;
        }
        if(strcmp(line,"END connect-blacklist") == 0) break;
        if(start){
            char tmp[256], *token, *hostname, *port;
            strcpy(tmp, line);
            token = strtok(tmp, ":");
            if(token != NULL){
                hostname = token;
                token = strtok(NULL, ":");
                if(token != NULL){
                    port = token;
                }
            }
            // printf("%s %s %s\n", line, hostname, port);

            struct addrinfo hints, *result, *next;
            memset(&hints, 0, sizeof(hints));
            hints.ai_flags = AI_CANONNAME;
            hints.ai_family = PF_UNSPEC;
            hints.ai_protocol = 0;
            hints.ai_socktype = 0;

            getaddrinfo(hostname, port, &hints, &result);
            // printf("%d\n", stat);

            while(true){
                next = result->ai_next;
                if(next == NULL) break;

                struct sockaddr_in *bip = (struct sockaddr_in *)(result->ai_addr);
                char blackIp[64];
                strcpy(blackIp, inet_ntoa(bip->sin_addr));
                // printf("%s\n", blackIp);
                
                if(strcmp(blackIp, connectIp) == 0){
                    errno = ECONNREFUSED;
                    ret = -1;
                    fclose(f);
                    sprintf(logger, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, connectIp, addrlen, ret);
                    write(loggerFd, logger, strlen(logger));
                    return ret;
                }

                result = next;
            }
        }
    }
    fclose(f);

    ret = connect(sockfd, addr, addrlen);

    sprintf(logger, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, connectIp, addrlen, ret);
    write(loggerFd, logger, strlen(logger));

    return ret;
}

int myGetaddrinfo(const char *restrict node,
            const char *restrict service,
            const struct addrinfo *restrict hints,
            struct addrinfo **restrict res){
    // printf("==my getaddressinfo==\n");
    char logger[1024];
    int loggerFd = atoi(getenv("LOGGER_FD"));

    FILE *f = fopen(getenv("SANDBOX_CONFIG"),"r");
    // FILE *f = fopen("config-example.txt","r");
    // FILE *f = fopen("config.txt","r");
    char buf[256];
    int ret = 0;

    bool start = false;
    while(!feof(f)){
        fgets(buf, 256, f);
        buf[strcspn(buf,"\r\n")] = '\0';
        // printf("%s\n",buf);
        if(strcmp(buf,"BEGIN getaddrinfo-blacklist") == 0){
            start = true;
            continue;
        }
        if(strcmp(buf,"END getaddrinfo-blacklist") == 0){
            ret = getaddrinfo(node, service, hints, res);
            break;
        }
        if(start){
            if(strcmp(buf,node) == 0){
                ret = EAI_NONAME;
                sprintf(logger, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, ret);
                write(loggerFd, logger, strlen(logger));

                fclose(f);
                return ret;
            } 
        }
    }
    
    fclose(f);
    sprintf(logger, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, ret);
    write(loggerFd, logger, strlen(logger));
    
    return ret;
}

int mySystem(const char *command){
    char logger[1024];
    int loggerFd = atoi(getenv("LOGGER_FD"));

    sprintf(logger, "[logger] system(\"%s\")\n", command);
    write(loggerFd, logger, strlen(logger));

    return system(command);
}

int __libc_start_main(int (*main)(int, char **, char **),
                      int argc, 
                      char **argv,
                      void (*init)(void),
                      void (*fini)(void),
                      void (*rtld_fini)(void),
                      void (*stack_end)){

    // get origin __libc_start_main
    void *handle = dlopen("/lib/x86_64-linux-gnu/libc.so.6", RTLD_LAZY);
    
    if (!handle) {
        fprintf (stderr, "%s\n", dlerror());
        exit(1);
    }

    void (*func) = dlsym(handle, "__libc_start_main");
    // get logger_fd
    // char *logger_fd = getenv("LOGGER_FD");
    // int loggerFd = atoi(logger_fd);
    // printf("%d\n", loggerFd);
    // write(loggerFd, "hello\n", 10);

    
    // clear LD_PRELOAD
    // setenv("LD_PRELOAD", "", 1);
    // printf("%d",setenv("LD_PRELOAD", "", 1));
    // printf("%s\n", getenv("LD_PRELOAD"));

    // get base address
    long baseAddr = getBaseAddress();
    // printf("base address: %lx\n", baseAddr);

    // // get got offset
    char *opList[6] = {"open", "read", "write", "connect", "getaddrinfo", "system"};
    int opSymIndex[6] = {-1,-1,-1,-1,-1,-1};
    long *funcAddr[6] = {&myOpen, &myRead, &myWrite, &myConnect, &myGetaddrinfo, &mySystem};
    long gotOffset[6] = {NULL}; 
    long *gotAddr[6] = {NULL}; 

    // get execute elf
    char elfFile[256];
    readlink("/proc/self/exe", elfFile, 256);
    // printf("%s\n", elfFile);
    FILE *f;
    if((f = fopen(elfFile, "rb")) < 0) {
        errquit("open elf file error");
    }

    Elf64_Ehdr elfHdr;
    Elf64_Shdr elfSecHdr, elfStrTab;
    Elf64_Sym elfSym;
    Elf64_Rela elfRela;
    // read the elf header
    fread(&elfHdr, sizeof(elfHdr), 1, f);

    // find the symbol table (func)
    for(int i=0;i<elfHdr.e_shnum;i++){ 
        // section header table's offset + index * sections header's size
        fseek(f, elfHdr.e_shoff + i*sizeof(elfSecHdr), SEEK_SET); 
        fread(&elfSecHdr, sizeof(elfSecHdr), 1, f);
        if(elfSecHdr.sh_type == SHT_SYMTAB || elfSecHdr.sh_type == SHT_DYNSYM){
            // find symbol string table (idx <-> string name)
            fseek(f, elfHdr.e_shoff + elfSecHdr.sh_link * sizeof(elfSecHdr), SEEK_SET); // sh_link -> idx of string table belonging to the section header 
            fread(&elfStrTab, sizeof(elfStrTab), 1, f);
            char* SymNameTab = NULL;
            SymNameTab = malloc(elfStrTab.sh_size);
            // go to string table
            fseek(f, elfStrTab.sh_offset, SEEK_SET);
            fread(SymNameTab, elfStrTab.sh_size, 1, f);
            // go to symbol table
            fseek(f, elfSecHdr.sh_offset, SEEK_SET);
            for(int j=0;j<elfSecHdr.sh_size / sizeof(elfSym);j++){
                fread(&elfSym, sizeof(elfSym), 1, f);
                char* name = SymNameTab + elfSym.st_name;
                for(int z=0;z<6;z++){
                    if(strcmp(name,opList[z]) == 0){
                        opSymIndex[z] = j;
                        // printf("%s %d\n", name,opSymIndex[z]);
                    }
                }
                // printf("%d %s\n", i, name);
            }
        }
    }
    
    // find STRTAB (.shstrtab) -> string table that contains the section header name
    fseek(f, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof(elfSecHdr), SEEK_SET); 
    fread(&elfStrTab, sizeof(elfStrTab), 1, f);
    char* SecNameTab = NULL;
    SecNameTab = malloc(elfStrTab.sh_size);
    // go to string table
    fseek(f, elfStrTab.sh_offset, SEEK_SET);
    fread(SecNameTab, elfStrTab.sh_size, 1, f);
    for(int i=0;i<elfHdr.e_shnum;i++) {
        // loop each section
        fseek(f, elfHdr.e_shoff + i * sizeof(elfSecHdr), SEEK_SET); // section header table's offset + index * sections header's size
        fread(&elfSecHdr, sizeof(elfSecHdr), 1, f);
        // print section name(section name string table + string table id)
        char* name = SecNameTab + elfSecHdr.sh_name;
        if(strcmp(name, ".rela.plt") == 0) {
            // printf("%s %lx %lx %lx\n", name, elfSecHdr.sh_addr, elfSecHdr.sh_offset, elfSecHdr.sh_size);
            fseek(f, elfSecHdr.sh_offset, SEEK_SET);
            for(int j=0;j<elfSecHdr.sh_size/sizeof(elfRela);j++) {
                fread(&elfRela, sizeof(elfRela), 1, f);
                for(int z=0;z<6;z++){
                    if(opSymIndex[z] == ELF64_R_SYM(elfRela.r_info)){
                        gotOffset[z] = elfRela.r_offset;
                        // printf("%s %lx\n", opList[z], gotOffset[z]);
                    }
                }
                // printf("%lx %d\n", elfRela.r_offset, ELF64_R_SYM(elfRela.r_info));
            }
        }
    }

    fclose(f);

    // hijack got table
    for(int i=0;i<6;i++){
        if(opSymIndex[i] != -1){
            gotAddr[i] = (long *)(gotOffset[i] + baseAddr);
            // make the region writable
            int pagesize = sysconf(_SC_PAGE_SIZE);
            void *nearBaseAddr = (void *)(gotOffset[i] / pagesize * pagesize + baseAddr);
            if (mprotect((void *)nearBaseAddr, pagesize,  PROT_WRITE | PROT_READ) == -1) 
                perror("mprotect fail to change the privilege\n");

            // *gotAddr[i] = (long *)funcAddr[i];
            memcpy(gotAddr[i], &funcAddr[i], 8);
        }
    }

    // system("ls");

    // printf("==call origin libc_start_main==\n");
    int (*libc_start_main)(int (*main)(int, char **, char **),
                            int argc, 
                            char **argv,
                            void (*init)(void),
                            void (*fini)(void),
                            void (*rtld_fini)(void),
                            void (*stack_end)) = func;

    exit(libc_start_main(main,argc,argv,init,fini,rtld_fini,stack_end));
}

