#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "udp.h"
#include "mfs.h"

int sd;
void* start; // the head ptr of the file system in memory

extern unsigned int get_bit(unsigned int *bitmap, int position);
extern void set_bit(unsigned int *bitmap, int position); 

int server_Lookup(int pinum, char *name);
int server_Stat(int inum, MFS_Stat_t *m);
int server_Write(int inum, char *buffer, int offset, int nbytes);
int server_Read(int inum, char *buffer, int offset, int nbytes);
int server_Creat(int pinum, int type, char *name);
int server_Unlink(int pinum, char *name);
int server_Shutdown();
int server_Error();

void intHandler(int dummy) {
    UDP_Close(sd);
    exit(130);
}
// server code
int main(int argc, char *argv[]) {
	signal(SIGINT, intHandler);

	if(argc != 3) return -1;
	int port = atoi(argv[1]);

	sd = UDP_Open(port);
    assert(sd > -1);
	struct sockaddr_in addr;
	UDP_FillSockAddr(&addr, "localhost", port);

	// open img file, convert it into ptr
	int fd = open(argv[2], O_RDWR);
	if(fd < 0){
		printf("image does not exist\n");
		exit(1);
	}
	struct stat sb;
	fstat(fd, &sb);
	start = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);


    while (1) {
		MFS_Msg_t msg;
		printf("server:: waiting...\n");
		int rc = UDP_Read(sd, &addr, (char*)&message, BUFFER_SIZE);
		printf("server:: read message [size:%d contents:(%s)]\n", rc, message);

		// here
		if(rc < 0) continue;
		switch(msg.msg_type):
			MFS_LOOKUP:
				server_Lookup(msg.inum, (char*)msg.buf);
				break;
			MFS_STAT:
				msg.buf = (void*)msg.buf;
				server_Stat(msg.inum, (MFS_Stat_t*)msg.buf);
				break;
			MFS_WRITE:
				server_Write(msg.inum, (char*)msg.buf, msg.offset,msg.nbytes);
				break;
			MFS_READ:
				server_Read(msg.inum, (char*)msg.buf, msg.offset, msg.nbytes);
				break;
			MFS_CREAT:
				server_Creat(msg.inum, msg.type, (char*)msg.buf);
				break;
			MFS_UNLINK:
				server_Unlink(msg.inum, (char*)msg.buf);
				break;
			MFS_SHUTDOWN:
				server_Shutdown();
				break;
			default:
				server_Error();
				break;
		if (rc > 0) {
	      	char reply[BUFFER_SIZE];
    	    sprintf(reply, "goodbye world");
        	rc = UDP_Write(sd, &addr, reply, BUFFER_SIZE);
	    	printf("server:: reply\n");
		} 
    }
    return 0; 
}


