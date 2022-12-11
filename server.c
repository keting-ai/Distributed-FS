#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "udp.h"
#include "mfs.h"
#include "ufs.h"

int sd;
void* start; // the head ptr of the file system in memory
super_t* super; // super block addr
void* inbm_addr; // inode bitmap addr
void* dbm_addr; // data bitmap addr
void* inrg_addr; // inode region addr
void* drg_addr; // data region addr

struct sockaddr_in saddr, caddr;

extern unsigned int get_bit(unsigned int *bitmap, int position);
extern void set_bit(unsigned int *bitmap, int position); 

int server_Lookup(int pinum, char *name){
    // check bitmap availability
    // check the inode, get data block number
    // check if it's directory
    // check data block availability
    // go the the data and find the data
    // return inum
    // every block can contain up to 127 directory entries
    // one directory entry uses 32 bytes
    MFS_Msg_t reply;
    reply.msg_type = MFS_LOOKUP;
    unsigned int inode_bit = get_bit(inbm_addr, pinum);
    if(!inode_bit){
        // send 
        reply.inum = -1;
        UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
        return -1;
    }
    inode_t* inode = inrg_addr + pinum * UFS_BLOCK_SIZE;
    if(inode->type != UFS_DIRECTORY){
        reply.inum = -1;
        UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
        return -1;
    }
    int size = inode->size;
    int entry_num = (UFS_BLOCK_SIZE / sizeof(dir_ent_t)) * (size / UFS_BLOCK_SIZE) + size % UFS_BLOCK_SIZE; // niubi algorithm
    int num_block = size / UFS_BLOCK_SIZE + 1;
    unsigned int data_blocks[num_block]; // stores the blocks' addr (in blocks)
    dir_ent_t* entries[entry_num];
    for(int i = 0; i < num_block; i++){
        data_blocks[i] = inode->direct[i];
    }
    // fill in the entries
    int remain_entry = entry_num;
    for(int i = 0; i < num_block; i++){
        unsigned int data_block = data_blocks[i];
        unsigned int data_addr = data_block * UFS_BLOCK_SIZE;
        if(!get_bit(dbm_addr, data_block)){
            reply.inum = -1;
            UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
            return -1;
        }
        int loopend;
        if(remain_entry < UFS_BLOCK_SIZE / sizeof(dir_ent_t)){
            loopend = remain_entry;
        }else{
            loopend = UFS_BLOCK_SIZE / sizeof(dir_ent_t);
        }
        void* data_ptr = (void*)(intptr_t)data_addr;
        for(int j = 0; j < loopend; j++){
            entries[j + (UFS_BLOCK_SIZE / sizeof(dir_ent_t)) * i] = (dir_ent_t*)data_ptr;
            remain_entry--;
            data_ptr += sizeof(dir_ent_t);
        }
    }

    // compare entries' names with name
    for(int i = 0; i < entry_num; i++){
        if(!strcmp(name, entries[i]->name)){
            // found
            reply.inum = entries[i]->inum;
            UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
            return 0;
        }
    }
    return -1;
}
int server_Stat(int inum){
    MFS_Msg_t reply;
    reply.msg_type = MFS_STAT;
    unsigned int inode_bit = get_bit(inbm_addr, inum);
    if(!inode_bit){
        reply.inum = -1;
        UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
        return -1;
    }
    inode_t* inode = inrg_addr + inum * UFS_BLOCK_SIZE;
    int type = inode->type;
    int size = inode->size;
    MFS_Stat_t stat;
    stat.type = type;
    stat.size = size;
    reply.inum = inum;
    memcpy(reply.buf, &stat, sizeof(MFS_Stat_t));
    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
    return 0;
}
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
    // Here, caddr should not be "localhost" if we want to run this on
    // different machines.
    UDP_FillSockAddr(&caddr, "localhost", port);

    // open img file, convert it into ptr
    int fd = open(argv[2], O_RDWR);
    if(fd < 0){
        printf("image does not exist\n");
        exit(1);
    }
    struct stat sb;
    fstat(fd, &sb);
    start = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    super = start;
    inbm_addr = start + super->inode_bitmap_addr * UFS_BLOCK_SIZE;
    dbm_addr = start + super->data_bitmap_addr * UFS_BLOCK_SIZE;
    inrg_addr = start + super->inode_region_addr * UFS_BLOCK_SIZE;
    drg_addr = start + super->data_region_addr * UFS_BLOCK_SIZE;

    while (1) {
        MFS_Msg_t msg;
        printf("server:: waiting...\n");
        int rc = UDP_Read(sd, &caddr, (char*)&msg, MFS_BUFFER);
        printf("server:: read message [size:%d contents:(%s)]\n", rc, (char*)&msg);

        // here
        if(rc < 0) continue;
        switch(msg.msg_type){
            case MFS_LOOKUP:
                server_Lookup(msg.inum, (char*)msg.buf);
                break;
            case MFS_STAT:
                server_Stat(msg.inum);
                break;
            case MFS_WRITE:
                server_Write(msg.inum, (char*)msg.buf, msg.offset, msg.nbytes);
                break;
            case MFS_READ:
                server_Read(msg.inum, (char*)msg.buf, msg.offset, msg.nbytes);
                break;
            case MFS_CREAT:
                server_Creat(msg.inum, msg.creat_type, (char*)msg.buf);
                break;
            case MFS_UNLINK:
                server_Unlink(msg.inum, (char*)msg.buf);
                break;
            case MFS_SHUTDOWN:
                server_Shutdown();
                break;
            default:
                server_Error();
                break;
        }
        if (rc > 0) {
            char reply[4096];
            sprintf(reply, "goodbye world");
            rc = UDP_Write(sd, &caddr, reply, MFS_BUFFER);
            printf("server:: reply\n");
        } 
    }
    return 0; 
}


