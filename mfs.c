#include "mfs.h"
#include "udp.h"
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <stdio.h>
#include <time.h>

static int sock_fd;
static struct timeval tv;
static struct sockaddr_in saddr, caddr;

/*
int send_rcv(char* message, char* respond){
    struct timeval tv;
    tv.tv_sec = 10; // timeout after 10 secs
    fd_set readfds;
    while(1){
        FD_ZERO(&readfds);
        FD_SET(sock_fd,&readfds);

        int send_rc = UDP_Write(sock_fd, &saddr, message, sizeof(MFS_Msg_t));
        if(send_rc < 0){
            return -1;
        }
        // a timer
        if(select(sock_fd+1, &readfds, NULL, NULL, &tv) < 0){
            return -1;
        }
        if(FD_ISSET(sock_fd,&readfds)){
            int rcv_rc = UDP_Read(sock_fd, &saddr, respond, sizeof(MFS_Msg_t));
            if(rcv_rc < 0) {
                return -1;
            }
            MFS_Msg_t* rsp = (void*)respond; 
            printf("CLIENT:: Type:%d Inum:%d Block:%d Message:%s\n", 
                rsp->msg_type, rsp->inum, rsp->offset, (char *)rsp->buf);
            break;
        }
        // else send and receive again
    }
    return 0;
}
*/

int send_rcv(char* message, char* respond){
    int send_rc = UDP_Write(sock_fd, &saddr, message, sizeof(MFS_Msg_t));
    int rcv_rc = UDP_Read(sock_fd, &saddr, respond, sizeof(MFS_Msg_t));
    return rcv_rc;
}

int MFS_Init(char *hostname, int port){
    int MIN_PORT = 20000;
    int MAX_PORT = 40000;

    srand(time(0));
    int port_num = (rand() % (MAX_PORT - MIN_PORT) + MIN_PORT);
    sock_fd = UDP_Open(port_num);
    if (sock_fd < 0) {
        return sock_fd;
    }
    int rc = UDP_FillSockAddr(&saddr, hostname, port);
    if (rc < 0) {
        return rc;
    } 
    return 0;
}

int MFS_Lookup(int pinum, char *name){
    if(strlen(name) > 27) return -1;
    //int send_rc, rcv_rc;
    MFS_Msg_t message, respond;
    message.msg_type = MFS_LOOKUP;
    message.inum = pinum;
    strcpy(message.buf, name);
    if(send_rcv((char*)&message, (char*)&respond) < 0){
        return -1;
    }
    if(respond.msg_type != MFS_LOOKUP) return -1;
    if(respond.inum < 0) return -1;
    return respond.inum;
}

int MFS_Stat(int inum, MFS_Stat_t *m){
    MFS_Msg_t message, respond;
    message.msg_type = MFS_STAT;
    message.inum = inum;
    if(send_rcv((char*)&message, (char*)&respond) < 0){
        return -1;
    }
    if(respond.msg_type != MFS_STAT) return -1;
    if(respond.inum < 0) return -1;
    // m is in the buffer
    memcpy(m, respond.buf, sizeof(MFS_Stat_t));
    return 0;
}

int MFS_Write(int inum, char *buffer, int offset, int nbytes){
    if(nbytes > MFS_BUFFER) return -1;
    MFS_Msg_t message, respond;
    message.msg_type = MFS_WRITE;
    message.inum = inum;
    memcpy((char*)message.buf, buffer, nbytes);
    //printf("DEBUG: client write\n");
    /*
    for(int i = 0; i < nbytes; i++){
        printf("%c", message.buf[i]);
    }
    printf("\n");*/
    message.offset = offset;
    message.nbytes = nbytes;
    if(send_rcv((char*)&message, (char*)&respond) < 0){
        return -1;
    }
    if(respond.msg_type != MFS_WRITE){
        printf("here1\n");
        return -1;
    }
    if(respond.inum < 0){ 
        printf("here2\n");
        return -1;
    }
    return 0;
}

int MFS_Read(int inum, char *buffer, int offset, int nbytes){
    if(nbytes > MFS_BUFFER) return -1;
    MFS_Msg_t message, respond;
    message.msg_type = MFS_READ;
    message.inum = inum;
    message.offset = offset;
    message.nbytes = nbytes;
    if(send_rcv((char*)&message, (char*)&respond) < 0){
        return -1;
    }
    if(respond.msg_type != MFS_READ) return -1;
    if(respond.inum < 0) return -1;
    memcpy(buffer, respond.buf, nbytes);
    return 0;
}

int MFS_Creat(int pinum, int type, char *name){
    if(strlen(name) > 27) return -1;
    MFS_Msg_t message, respond;
    message.msg_type = MFS_CREAT;
    message.inum = pinum;
    strcpy(message.buf, name);
    message.creat_type = type;
    if(send_rcv((char*)&message, (char*)&respond) < 0){
        return -1;
    }
    if(respond.msg_type != MFS_CREAT) return -1;
    if(respond.inum < 0) return -1;
    return 0;
}

int MFS_Unlink(int pinum, char* name){
    if(strlen(name) > 27) return -1;
    MFS_Msg_t message, respond;
    message.msg_type = MFS_UNLINK;
    message.inum = pinum;
    strcpy(message.buf, name);
    if(send_rcv((char*)&message, (char*)&respond) < 0){
        return -1;
    }
    if(respond.msg_type != MFS_UNLINK) return -1;
    if(respond.inum < 0) return -1;
    return 0;
}

int MFS_Shutdown(){
    MFS_Msg_t message, respond;
    message.msg_type = MFS_SHUTDOWN;
    if(send_rcv((char*)&message, (char*)&respond) < 0){
        return 0;
    }
    if(respond.msg_type != MFS_SHUTDOWN) return -1;
    UDP_Close(sock_fd);
    return 0;
}
