#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <capstone/capstone.h>

// #include "ptools.h"

#include <iostream>
#include <string>
#include <map>
#include <elf.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>   
#include <vector>
#include <fstream>
#include <sstream>
#include <cstring>

using namespace std;

#define	PEEKSIZE	8

class instruction1 {
public:
	unsigned char bytes[16];
	int size;
	string opr, opnd;
};

// class instruction_cc {
// public:
// 	unsigned char origin[8];
// 	unsigned char modify[8];
// };

class anchorMem {
public:
	char *memory;
	char *start, *end;
	unsigned long long size;
};

static csh cshandle = 0;
static map<unsigned long long, instruction1> instructions;
unsigned long long programTextAddr, programTextSize; 
static map<unsigned long long, instruction1> breakPoints;
vector<anchorMem> anchorMemList;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

void print_instruction(unsigned long long addr, instruction1 *in) {
	int i;
	char bytes[128] = "";
	if(in == NULL) {
		printf("%12llx:\t<cannot disassemble>\n", addr);
	} else {
		for(i = 0; i < in->size; i++) {
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		}
		printf("%12llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());
	}
}

void disassemble(pid_t proc, unsigned long long rip, unsigned long long size) {
	int count;
	char buf[size] = { 0 };
	unsigned long long ptr = rip;
	cs_insn *insn;

	// get the byte codes of the proc
	for(ptr = rip; ptr < rip + sizeof(buf); ptr += PEEKSIZE) {
		long long peek;
		errno = 0;
		peek = ptrace(PTRACE_PEEKTEXT, proc, ptr, NULL);
		if(errno != 0) break;
		memcpy(&buf[ptr-rip], &peek, PEEKSIZE);
	}

	// size == 0
	if(ptr == rip)  {
		print_instruction(rip, NULL);
		return;
	}

	if((count = cs_disasm(cshandle, (uint8_t*) buf, size, rip, 0, &insn)) > 0) {
		int i;
		// store the instruction into map
		for(i = 0; i < count; i++) {
			instruction1 in;
			in.size = insn[i].size;
			in.opr  = insn[i].mnemonic;
			in.opnd = insn[i].op_str;
			memcpy(in.bytes, insn[i].bytes, insn[i].size);
			instructions[insn[i].address] = in;
			
		}
		cs_free(insn, count);
	}

	// map<long long, instruction1>::iterator mi; // from memory addr to instruction
	// for(mi=instructions.begin(); mi != instructions.end(); ++mi) {
	// 	print_instruction(mi->first, &mi->second);
	// }

	return;
}

void print_next_instruction(unsigned long long addr){
	// from memory addr to instruction
	map<unsigned long long, instruction1>::iterator mi; 
	int i;

	for(mi=instructions.find(addr), i=0;i<5;++mi, ++i) {
		if(mi != instructions.end()){
			print_instruction(mi->first, &mi->second);
		}else{
			printf("** the address is out of the range of the text section.\n");
			return;
		}
	}
}

int
main(int argc, char *argv[]) {
	pid_t child;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
		long long counter = 0LL;

		// get the entrypoint and section size 
		FILE *f;
		if((f = fopen(argv[1], "rb")) == NULL) {
			errquit("open elf file error");
		}

		Elf64_Ehdr elfHdr;
		Elf64_Shdr elfSecHdr, elfStrTab;

		// read the elf header
		fread(&elfHdr, sizeof(elfHdr), 1, f);

		// find STRTAB (.shstrtab) -> string table that contains the section header name
		fseek(f, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof(elfSecHdr), SEEK_SET); 
		fread(&elfStrTab, sizeof(elfStrTab), 1, f); // find the str section header table
		char* SecNameTab = NULL;
		SecNameTab = (char *)malloc(elfStrTab.sh_size);
		fseek(f, elfStrTab.sh_offset, SEEK_SET);  // go to string table section
		fread(SecNameTab, elfStrTab.sh_size, 1, f); // get the section content (each entry is a section name)
		
		// find .text section
		for(int i=0;i<elfHdr.e_shnum;i++) {
			// loop each section
			fseek(f, elfHdr.e_shoff + i * sizeof(elfSecHdr), SEEK_SET);
			fread(&elfSecHdr, sizeof(elfSecHdr), 1, f);

			// section name
			char* name = SecNameTab + elfSecHdr.sh_name; // SecNameTab[idx]
			if(strcmp(name, ".text") == 0) {
				programTextAddr = elfSecHdr.sh_addr;
				programTextSize = elfSecHdr.sh_size;
				// printf("%llx %llx\n", programTextAddr, programTextSize);
				break;
			}
		}
		fclose(f);

		int wait_status;
		struct user_regs_struct regs;

		if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
			return -1;

		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

		// disassemble all the program text 
		disassemble(child, programTextAddr, programTextSize);

		// print the name of the executable and the entry point address.
		if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
			printf("** program '%s' loaded. entry point 0x%llx\n", argv[1], regs.rip);
			print_next_instruction(regs.rip);
		}
		

		// wait for instruction
		string inst;
		char memFilePath[32];
		struct user_regs_struct anchorRegs;

		cout << "(sdb) ";
		while(getline(cin, inst)){
			if(inst == "si"){ // step instruction

				// check whether hit the breakpoint
				bool hit = false;
				unsigned long long hitRip;
				if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {

					if(breakPoints.find(regs.rip) != breakPoints.end()){
						hit = true;
						hitRip = regs.rip;
					}
				}

				unsigned char currentBytes[8];

				// skip the breakpoint
				if(hit == true){
					// get the break point bytes
					long long peek;
					errno = 0;
					peek = ptrace(PTRACE_PEEKTEXT, child, hitRip, NULL);
					if(errno != 0) break;
					memcpy(currentBytes, &peek, PEEKSIZE);

					currentBytes[0] = breakPoints.find(hitRip)->second.bytes[0];
					// cout << currentBytes[0];
					
					if(ptrace(PTRACE_POKETEXT, child, hitRip, *(unsigned long*)currentBytes) < 0){
						errquit("skip break point error in si");
					}
				}

				// single step
				if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) {
					perror("ptrace single step");
					cs_close(&cshandle);
					return -2;
				}

				if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
				if(WIFEXITED(wait_status)) break;

				// check whether 'rip' hit the breakpoint (after si)
				if(ptrace(PTRACE_GETREGS, child, 0 ,&regs) == 0){
					// print hit the breakpoint info
					if(breakPoints.find(regs.rip) != breakPoints.end()){
						printf("** hit a breakpoint at 0x%llx.\n", breakPoints.find(regs.rip)->first);					
					}
					// print instructions
					print_next_instruction(regs.rip);
				}

				// recover the breakpoint
				if(hit == true){
					currentBytes[0] = 0xCC;
					if(ptrace(PTRACE_POKETEXT, child, hitRip, *(unsigned long*)currentBytes) < 0){
						errquit("skip break point error in si\n");
					}
					hit = false;
				}

			}
			else if(inst == "cont"){
				// check whether hit the breakpoint
				bool hit = false;
				unsigned long long hitRip;
				if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
					if(breakPoints.find(regs.rip) != breakPoints.end()){
						hit = true;
						hitRip = regs.rip;
					}
				}

				unsigned char currentBytes[8];

				if(hit == true){
					// skip the breakpoint
					long long peek;
					errno = 0;
					peek = ptrace(PTRACE_PEEKTEXT, child, hitRip, NULL);
					if(errno != 0) break;
					memcpy(currentBytes, &peek, PEEKSIZE);

					currentBytes[0] = breakPoints.find(hitRip)->second.bytes[0];
					// cout << currentBytes[0];
					
					if(ptrace(PTRACE_POKETEXT, child, hitRip, *(unsigned long*)currentBytes) < 0){
						errquit("skip break point error in si");
					}

					// single step
					if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) {
						perror("ptrace single step");
						cs_close(&cshandle);
						return -2;
					}

					if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
					if(WIFEXITED(wait_status)) break;

					// recover the cc
					currentBytes[0] = 0xCC;
					if(ptrace(PTRACE_POKETEXT, child, hitRip, *(unsigned long*)currentBytes) < 0){
						errquit("skip break point error in si\n");
					}
					hit = false;
				}

				// continue
				if(ptrace(PTRACE_CONT, child, 0, 0) < 0) {
					perror("ptrace continue");
					cs_close(&cshandle);
					return -2;
				}

				if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
				if(WIFEXITED(wait_status)){
					break;	
				}else if(WIFSTOPPED(wait_status)){ // stuck at the CC
					// check whether 'rip' hit the breakpoint (after si)
					if(ptrace(PTRACE_GETREGS, child, 0 ,&regs) == 0){
						// adjust teh rip
						regs.rip = regs.rip - 1;
						// print hit the breakpoint info
						if(breakPoints.find(regs.rip) != breakPoints.end()){
							printf("** hit a breakpoint at 0x%llx.\n", breakPoints.find(regs.rip)->first);					
							// print instructions
							print_next_instruction(regs.rip);
							
							ptrace(PTRACE_SETREGS, child, 0, &regs);
						}
					}
				}

				// ptrace(PTRACE_GETREGS, child, 0, &regs);
				// cout << regs.rip << endl;

			}
			else if(inst.substr(0,5) == "break"){
				// get break point address
				unsigned long long breakPoint = stoull(inst.substr(8), nullptr, 16);

				unsigned char originBytes[8];
				long long peek;
				errno = 0;
				// get the break point bytes
				peek = ptrace(PTRACE_PEEKTEXT, child, breakPoint, NULL);
				if(errno != 0) break;
				memcpy(originBytes, &peek, PEEKSIZE);
				originBytes[0] = 0xCC;

				// store in the breakPoints
				breakPoints[breakPoint] = instructions[breakPoint];

				// poketext
				if(ptrace(PTRACE_POKETEXT, child, breakPoint, *(unsigned long *)originBytes) == 0){
					printf("** set a breakpoint at 0x%llx.\n", breakPoint);
				}

				// for(int i = 0; i < 8; ++ i) {
				// 	printf("%x ", breakPoints[breakPoint].modify[i]);
				// }
				// cout << endl;

			}
			else if(inst == "anchor"){
				// snapshot the process memory
				if(anchorMemList.empty() == false){
					anchorMemList.clear();
				}
				
				sprintf(memFilePath, "/proc/%d/maps", child);
				fstream memFile(memFilePath, ios::in);
				string line = "";
				// get the memory mapiping
				while(getline(memFile, line, '\n')){
					stringstream ss(line);
					string content[6] = {"","","","","",""};

					ss >> content[0] >> content[1] >> content[2] >> content[3] >> content[4] >> content[5];
					// printf("%s %s\n", content[0].c_str(), content[1].c_str());

					if(content[5] == ""){
						continue;
					}

					// get the memory that are writable
					if(content[1].find("w") != string::npos && content[5].find(".so") == string::npos){
						// printf("%s %s\n", content[0].c_str(), content[1].c_str());
						unsigned long long start = 0, end = 0;
						sscanf(line.c_str(), "%llx-%llx", &start, &end);

						char *mem = (char*)calloc(end-start, sizeof(char));

						// store memory
						long long peek;
						errno = 0;
						for(unsigned long long i = start; i < end; i += 8LL){
							peek = ptrace(PTRACE_PEEKDATA, child, i, NULL);
							if(errno != 0) break;
							memcpy(mem + (i - start), &peek, PEEKSIZE);
						}

						anchorMem anchor;
						anchor.start = (char *)start;
						anchor.end = (char *)end;
						anchor.size = end-start;
						anchor.memory = mem;

						anchorMemList.push_back(anchor);

					}
				}	
				// printf("%ld\n", anchorMemList.size());
				memFile.close();	

				// snapshot the register
				if(ptrace(PTRACE_GETREGS, child, 0 ,&anchorRegs) == 0){
					printf("** dropped an anchor\n");
				}

			}
			else if(inst == "timetravel"){
				// recover the process memory
				// all anchor
				for (int i=0;i<anchorMemList.size();i++){
					// recover memory
					for(unsigned long long j=0LL;j<anchorMemList[i].size;j+=8LL){
						if(ptrace(PTRACE_POKETEXT, child, anchorMemList[i].start + j, *(unsigned long *)(anchorMemList[i].memory+j)) < 0){
							printf("** recover memory error\n");
						}
					}
				}

				// recover the register
				if(ptrace(PTRACE_SETREGS, child, 0 ,&anchorRegs) == 0){
					printf("** go back to the anchor point\n");
					print_next_instruction(anchorRegs.rip);
				}
			}

			cout << "(sdb) ";
		}


		// fprintf(stderr, "## %lld instructions(s) monitored\n", counter);
		
		printf("** the target program terminated.\n");
		cs_close(&cshandle);
	}

	return 0;
}

