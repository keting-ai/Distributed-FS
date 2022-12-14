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
int fd;
int img_sz;
void* start; // the head ptr of the file system in memory
super_t* super; // super block addr
void* inbm_addr; // inode bitmap addr
void* dbm_addr; // data bitmap addr
void* inrg_addr; // inode region addr
void* drg_addr; // data region addr

struct sockaddr_in saddr, caddr;

extern unsigned int get_bit(unsigned int *bitmap, int position);
extern void set_bit(unsigned int *bitmap, int position);

int server_Error(MFS_Msg_t* reply){
    reply->inum = -1;
    void* r = (void*)reply;
    UDP_Write(sd, &caddr, (char*)r, sizeof(MFS_Msg_t));
    return 0;
}

int server_Stat(int inum){
    MFS_Msg_t reply;
    reply.msg_type = MFS_STAT;
    unsigned int inode_bit = get_bit(inbm_addr, inum);
    if(!inode_bit){
        server_Error(&reply);
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

// returns found directory entry pointer
void* lookup(int pinum, char *name){
    // check bitmap availability
    // check the inode, get data block number
    // check if it's directory
    // check data block availability
    // go the the data and find the data
    // return inum
    // every block can contain up to 127 directory entries
    // one directory entry uses 32 bytes
    void* rc_err = (void*)(intptr_t)-1;
    unsigned int inode_bit = get_bit(inbm_addr, pinum);
    if(!inode_bit){
        return rc_err;
    }
    inode_t* inode = inrg_addr + pinum * sizeof(inode_t);
    if(inode->type != UFS_DIRECTORY){
        return rc_err;
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
        if(!get_bit(dbm_addr, data_block - super->data_region_addr)){
            return rc_err;
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
            data_ptr = (void*)data_ptr;
            data_ptr += sizeof(dir_ent_t);
        }
    }

    // compare entries' names with name
    for(int i = 0; i < entry_num; i++){
        if(!strcmp(name, entries[i]->name)){
            // found
            return (void*)entries[i];
        }
    }
    return rc_err;
}

int server_Lookup(int pinum, char* name){
    MFS_Msg_t reply;
    reply.msg_type = MFS_LOOKUP;
    void* ptr = lookup(pinum, name);
    if(*(int*)ptr == -1){
        server_Error(&reply);
        return -1;
    }
    reply.inum = ((dir_ent_t*)ptr)->inum;
    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
    return 0;
}

int server_Write(int inum, char *buffer, int offset, int nbytes){
    MFS_Msg_t reply;
    reply.msg_type = MFS_WRITE;
    if(nbytes > MFS_BUFFER | !get_bit(inbm_addr, inum)){
        server_Error(&reply);
        return -1;
    }
    inode_t* inode = inrg_addr + inum * sizeof(inode_t);
    int size = inode->size;
    int type = inode->type;
    if(offset >= size | type == MFS_DIRECTORY){
        server_Error(&reply);
        return -1;
    }
    // find the start location of offset to write
    int start_blk = offset / 4095;
    int start_off = offset % 4095;
    int remain_bytes = nbytes;
    int blk_write_off = start_off;
    int buffer_off = 0;
    unsigned int this_block = inode->direct[start_blk]; // in blocks current writing block
    if(!get_bit(dbm_addr, this_block - super->data_region_addr)){ // if this block is unused
        server_Error(&reply);
        return -1;
    }
    unsigned int this_block_addr = this_block * UFS_BLOCK_SIZE;
    unsigned int cur_write_addr = this_block_addr + start_off;

    // write until this block is full
    // to another block(if there's following block, use that, otherwise use a unused)
    int i = 0;
    while(remain_bytes > 0){
        if(blk_write_off < 4096){
            *(char*)(void*)(intptr_t)cur_write_addr = *(buffer + buffer_off);
            cur_write_addr += 1;
            remain_bytes -= 1;
            buffer_off += 1;
            blk_write_off += 1;
        }else{
            // find the following block
            int flag = 0;
            while(start_blk + i < 30 && inode->direct[start_blk + i] != -1){
                // found
                if(inode->direct[start_blk + i] != -1){
                    this_block = inode->direct[start_blk + i];
                    this_block_addr = this_block * UFS_BLOCK_SIZE;
                    cur_write_addr = this_block_addr;
                    flag = 1;
                    blk_write_off = 0;
                    break;
                }
                i++;
            }
            if(start_blk + i >= 30){// TODO: error here, recover?
            }
            // not found
            // find a new one
            if(!flag){
                int j;
                for(j = 0; j < super->num_data; j++){
                    if(!get_bit(dbm_addr, j)) break; // found jth data block isn't used
                    // use jth data block
                    this_block = j + super->data_region_addr;
                    this_block_addr = this_block * UFS_BLOCK_SIZE;
                    cur_write_addr = this_block_addr;
                    // update inode direct
                    inode->direct[start_blk + i + 1] = this_block;
                    blk_write_off = 0;
                    // set jth data block to used
                    set_bit(dbm_addr, j);
                    break;                   
                }
                // no place remaining!
                // TODO: error here
            }
        }
    }
    // update inode
    inode->size += nbytes;
    // synchronize to disk
    if(msync(start, img_sz, MS_SYNC) == -1){
        server_Error(&reply);
        return -1;
    }
    // reply
    reply.inum = inum;
    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
    return 0;
}

int server_Read(int inum, char *buffer, int offset, int nbytes){
	MFS_Msg_t reply;
    reply.msg_type = MFS_READ;
    unsigned int inode_bit = get_bit(inbm_addr, inum);
    if(!inode_bit || nbytes > MFS_BUFFER || sizeof(buffer) > MFS_BLOCK_SIZE){
        server_Error(&reply);
        return -1;
    }
	inode_t* inode = inrg_addr + inum * UFS_BLOCK_SIZE;
    int size = inode->size;
    int type = inode->type;
    if(offset >= size){
        server_Error(&reply);
        return -1;
    }
    if(type != MFS_REGULAR_FILE || type != MFS_DIRECTORY){
        server_Error(&reply);
        return -1;
    }
    // find the start location of offset to read
    int start_blk = offset / 4096;
    int start_off = offset % 4096;
    int remain_bytes = nbytes;
    int blk_read_off = start_off;
    int buffer_off = 0;
    unsigned int this_block = inode->direct[start_blk]; // in blocks current writing block
    unsigned int this_block_addr = *((int*)start) + this_block * UFS_BLOCK_SIZE;
    unsigned int cur_read_addr = this_block_addr + start_off;

    // Directory case: cannot read if it doesn't read from start of each entry
    if(type == MFS_DIRECTORY && start_off % 32 != 0){
        server_Error(&reply);
        return -1;
    }

    // write until this block is full
    // to another block(if there's following block, use that, otherwise use a unused)
    int i = 0;
    while(remain_bytes > 0){
        if(blk_read_off < 4096){
            *(buffer + buffer_off) = *(char*)(void*)(intptr_t)cur_read_addr;
            cur_read_addr += 1;
            remain_bytes -= 1;
            buffer_off += 1;
            blk_read_off += 1;
        }else{
            // find the following block
            int flag = 0;
            while(start_blk + i < 30 && inode->direct[start_blk + i] != -1){
                // found
                if(inode->direct[start_blk + i] != -1){
                    this_block = inode->direct[start_blk + i];
                    this_block_addr = this_block * UFS_BLOCK_SIZE;
                    cur_read_addr = this_block_addr;
                    flag = 1;
                    blk_read_off = 0;
                    break;
                }
                i++;
            }
            // not found, error
            if(!flag){
                server_Error(&reply);
                return -1;
            }
        }
    }
    reply.inum = inum;
    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
}

int server_Creat(int pinum, int type, char *name){
    // remember to include \0 at the end of dir_ent_t's name field!
    MFS_Msg_t reply;
    reply.msg_type = MFS_UNLINK;
    unsigned int inode_bit = get_bit(inbm_addr, pinum);
    // pinum does not exist
    if(!inode_bit){
        server_Error(&reply);
        return -1;
    }
    inode_t* inode = inrg_addr + pinum * UFS_BLOCK_SIZE;
    int size = inode->size;
    int type = inode->type;
    // error if it's not the parent directory
    if(type != MFS_DIRECTORY){
        server_Error(&reply);
        return -1;
    }
    // int entry_num = (UFS_BLOCK_SIZE / sizeof(dir_ent_t)) * (size / UFS_BLOCK_SIZE) + size % UFS_BLOCK_SIZE / sizeof(dir_ent_t); // niubi algorithm
    // for 找最后一个不是-1的 如果写入entry 如果不能写入 则找新的block
    int block_idx = 0;
    while(inode->direct[block_idx] != -1){
        block_idx++;
    }
    block_idx--;
    unsigned int this_block = inode->direct[block_idx]; // in blocks current writing block
    unsigned int this_block_addr = *((int*)start) + this_block * UFS_BLOCK_SIZE;


    return 0;
}
int server_Unlink(int pinum, char *name){
    MFS_Msg_t reply;
    reply.msg_type = MFS_UNLINK;
    void* dir_entry = lookup(pinum, name);
    if(*(int*)dir_entry == -1){
        server_Error(&reply);
        return -1;
    }
    int inum = ((dir_ent_t*)dir_entry)->inum;
    if(!get_bit(inbm_addr, inum)){
        server_Error(&reply);
        return -1;
    }
    inode_t* inode_p = inrg_addr + pinum * sizeof(inode_t);
    inode_t* inode_c = inrg_addr + inum * sizeof(inode_t);
    int size = inode_c->size;
    if(inode_c->type == UFS_DIRECTORY && inode_c->size != 0){
        // check if its void
        server_Error(&reply);
    }
    // unlink
    // set this inode bitmap to zero
    set_bit(inbm_addr, inum);
    // set this data bitmap to zero
    int i = 0;
    while(inode_c->direct[i] != -1){
        int data_blk = inode_c->direct[i];
        set_bit(dbm_addr, data_blk - super->data_region_addr);
        i++;
    }
    // shift back a dir_ent_t in parent directory
    // FIXME: Not considered in separate blocks
    dir_ent_t* cur_dir = (dir_ent_t*)dir_entry;
    dir_ent_t* next_dir = cur_dir;
    unsigned int start_dir_addr = *(int*)(void*)cur_dir;
    unsigned int start_file_addr = *(int*)(void*)inode_p;
    int size_diff = start_dir_addr - start_file_addr;
    int size_remain = inode_p->size - size_diff;
    for(int i = 1; i < size_remain / sizeof(dir_ent_t); i += 1){
        next_dir += 1;
        memcpy(cur_dir, next_dir, sizeof(dir_ent_t));
        cur_dir += 1;
    }
    // set size
    inode_p->size -= sizeof(dir_ent_t);

    return 0;

}
int server_Shutdown(){
    return 0;
}

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
    fd = open(argv[2], O_RDWR);
    if(fd < 0){
        printf("image does not exist\n");
        exit(1);
    }
    struct stat sb;
    fstat(fd, &sb);
    img_sz = sb.st_size;
    start = mmap(NULL, img_sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
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
                server_Error(&msg);
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


