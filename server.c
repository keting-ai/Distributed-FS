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
    reply->msg_type = MFS_ERROR;
    reply->inum = -1;
    UDP_Write(sd, &caddr, (char*)(void*)r, sizeof(MFS_Msg_t));
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
    int entry_num = (UFS_BLOCK_SIZE / sizeof(dir_ent_t)) * (size / UFS_BLOCK_SIZE) + 
        ((size % UFS_BLOCK_SIZE) / sizeof(dir_ent_t)); // niubi algorithm
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
        unsigned int data_addr = data_block * UFS_BLOCK_SIZE; // relative address
        if(!get_bit(dbm_addr, data_block - super->data_region_addr)){
            return rc_err;
        }
        int loopend;
        if(remain_entry < UFS_BLOCK_SIZE / sizeof(dir_ent_t)){
            loopend = remain_entry;
        }else{
            loopend = UFS_BLOCK_SIZE / sizeof(dir_ent_t);
        }
        void* data_ptr = (void*)((intptr_t)data_addr + (intptr_t)start); // real address
        for(int j = 0; j < loopend; j++){
            entries[j + (UFS_BLOCK_SIZE / sizeof(dir_ent_t)) * i] = (dir_ent_t*)data_ptr;
            remain_entry--;
            data_ptr = (void*)data_ptr; // real address
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
    int start_blk = offset / 4096;
    int start_off = offset % 4096;
    int remain_bytes = nbytes;
    int blk_write_off = start_off;
    int buffer_off = 0;
    unsigned int this_block = inode->direct[start_blk]; // current writing block (in blocks)
    if(!get_bit(dbm_addr, this_block - super->data_region_addr)){ // if this block is unused
        server_Error(&reply);
        return -1;
    }
    unsigned int this_block_addr = this_block * UFS_BLOCK_SIZE; // relative addr
    unsigned int cur_write_addr = this_block_addr + start_off; // relative addr

    // write until this block is full
    // to another block(if there's following block, use that, otherwise use an unused)
    int i = 0;
    unsigned int write_addrs[nbytes]; // stores real addrs
    unsigned int data_block_use = -1; // extra data block number to use 
    //TODO: make it to an array for more than 4096 bytes per write
    while(remain_bytes > 0){
        if(blk_write_off < 4096){
            // write one byte by one byte
            // no real write here, just record to-write addresses
            write_addrs[buffer_off] = cur_write_addr;
            cur_write_addr += 1;
            remain_bytes -= 1;
            buffer_off += 1;
            blk_write_off += 1;
        }else{
            // find the following block
            int flag = 0;
            i += 1;
            if(start_blk + i >= DIRECT_PTRS){
                server_Error(&reply);
                return -1;
            }
            if(inode->direct[start_blk + i] != -1){
                // found
                this_block = inode->direct[start_blk + i];
                this_block_addr = this_block * UFS_BLOCK_SIZE;
                cur_write_addr = this_block_addr;
                flag = 1;
                blk_write_off = 0;
                continue;
            }            
            // following block is not used
            // find a new one
            int has_place = 0;
            if(!flag){
                int j;
                for(j = 0; j < super->num_data; j++){
                    if(get_bit(dbm_addr, j)) continue; // jth data block is used, continue find
                    // use jth data block
                    this_block = j + super->data_region_addr;
                    this_block_addr = this_block * UFS_BLOCK_SIZE;
                    cur_write_addr = this_block_addr;
                    blk_write_off = 0;
                    has_place = 1;
                    // jth data block will be used
                    data_block_use = this_block;
                    break;                   
                }
                // no place remaining!
                if(!has_place){
                    server_Error(&reply);
                    return -1;
                }
            }
        }
    }
    // real write here
    for(int i = 0; i < nbytes; i++){
        *(char*)(void*)(intptr_t)(write_addrs[i] + (intptr_t)start) = buffer[i]; // real address
    }
    set_bit(dbm_addr, data_block_use);
    // update inode
    inode->size += nbytes;
    for(int i = 0; i < DIRECT_PTRS; i++){
        if(inode->direct[i] == -1){
            inode->direct[i] = data_block_use + super->data_region_addr;
            break;
        }
    }
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
    unsigned int this_block_addr = this_block * UFS_BLOCK_SIZE;
    unsigned int cur_read_addr = this_block_addr + start_off;

    // Directory case: cannot read if it doesn't read from start of each entry
    if(type == MFS_DIRECTORY && start_off % 32 != 0){
        server_Error(&reply);
        return -1;
    }

    // read until this block is full
    // to another block(if there's following block, use that, otherwise use a unused)
    int i = 0;
    while(remain_bytes > 0){
        if(blk_read_off < 4096){
            *(buffer + buffer_off) = *(char*)(void*)(intptr_t)cur_read_addr + (intptr_t)start;
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

int get_inum(){
    for(int i = 0; i < super->num_inodes; i++){
        int bit = get_bit(inbm_addr, i);
        if(bit == 0) return i;
    }
    return -1;
}

int server_Creat(int pinum, int type, char *name){
    // remember to include \0 at the end of dir_ent_t's name field!
    MFS_Msg_t reply;
    reply.msg_type = MFS_CREAT;
    unsigned int inode_bit = get_bit(inbm_addr, pinum);
    // pinum does not exist
    if(!inode_bit){
        server_Error(&reply);
        return -1;
    }
    if(strlen(name) > 28){
        server_Error(&reply);
        return -1;
    }
    inode_t* inode_p = inrg_addr + pinum * UFS_BLOCK_SIZE;
    int p_size = inode_p->size;
    int p_type = inode_p->type;
    // error if it's not the parent directory
    if(p_type != MFS_DIRECTORY){
        server_Error(&reply);
        return -1;
    }

    // find place to add the new directory entry 
    int block_idx = 0;
    while(inode_p->direct[block_idx] != -1){
        block_idx++;
    }
    block_idx--; // the last valid block index
    unsigned int dir_block = inode_p->direct[block_idx]; // in blocks current writing block
    unsigned int block_addr = dir_block * UFS_BLOCK_SIZE;

    int entry_num = (UFS_BLOCK_SIZE / sizeof(dir_ent_t)) * (p_size / UFS_BLOCK_SIZE) + ((p_size % UFS_BLOCK_SIZE) / sizeof(dir_ent_t)); // niubi algorithm
    int remain_entry = (block_idx + 1) * 128 - entry_num; //the number of remaining entries in the last block
    dir_ent_t* entries[remain_entry];
    void* dir_block_addr = (void*)((intptr_t)block_addr + (intptr_t)start);; // real address
    int j;
    for(j = 0; j < remain_entry; j++){
        entries[j] = (dir_ent_t*)dir_block_addr;
        remain_entry--;
        dir_block_addr = (void*)dir_block_addr; // real address
        dir_block_addr += sizeof(dir_ent_t);
    }
    entries[j+1] = (dir_ent_t*)dir_block_addr;

    // if the last block is not full
    if(sizeof(entries) < (4096-32)){
        strcpy(entries[j+1]->name, name); //FIXME: 不知道能不能直接用entries
        entries[j+1]->inum = get_inum();
        set_bit(inbm_addr, get_inum());
    }
    // if full, find another
    if(sizeof(entries) >= (4096-32)){
        // find the following block
        unsigned int new_block;
        unsigned int new_block_addr;
        int flag = 0;
        int i = 0;
        while((block_idx + i) <= 30){
            if(inode_p->direct[block_idx + i] == -1){
                // found
                flag = 1;
                new_block = inode_p->direct[block_idx + i];
                new_block_addr = ((intptr_t)start + (intptr_t)new_block * UFS_BLOCK_SIZE); //real address
                entries[j+1] = (dir_ent_t*)dir_block_addr;
                strcpy((dir_ent_t*)new_block_addr->name, name);
                (dir_ent_t*)new_block_addr->inum = get_inum();
                set_bit(inbm_addr, get_inum());
                break;
            }
            i++;
        }
        // no blocks in this inode, error
        if(flag == 0){
            server_Error(&reply);
            return -1;
        }
                    
    }
    // set size of parent directory
    inode_p->size += sizeof(dir_ent_t);
    // if create regular file ...
    if(type == MFS_REGULAR_FILE){

    }
    // if create directory file ...
    if(type == MFS_DIRECTORY){

    }


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
        return -1;
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
    dir_ent_t* cur_dir = (dir_ent_t*)dir_entry;
    dir_ent_t* next_dir = cur_dir;
    unsigned int start_dir_addr = *(int*)(void*)cur_dir - (intptr_t)start; // relative address
    unsigned int start_dir_block = start_dir_addr / 4096; // the start editing block number
    unsigned int nth_block; // the nth block in parent directory file
    for(int i = 0; i < DIRECT_PTRS; i++){
        if(inode_p->direct[i] == start_dir_block){
            nth_block = i;
            break;
        }
    }
    unsigned int start_file_addr = inode_p->direct[0] * 4096; // the starting relative file addr
    int size_diff  = start_dir_addr % 4096 + nth_block * 4096;
    int size_remain = inode_p->size - size_diff;
    int cur_off_in_block = start_dir_addr % 4096 / sizeof(dir_ent_t); // current offset(in dir_ent_t) in one block
    int cur_block = nth_block;
    // one block has 0-127th dir_ent_t
    for(int i = 1; i < size_remain / sizeof(dir_ent_t); i += 1){
        if(cur_off_in_block == 127){ // the last dir_ent_t in one block
            // copy from the first dir_ent_t in the next block
            // then set cur_off_in_block to 0
            // set the cur_dir, next_dir to the first in the next block
            cur_block += 1;
            next_dir = inode_p->direct[cur_block];
            if(next_dir == -1){
                // no more data in this directory file, finish
                break;
            }
            memcpy(cur_dir, next_dir, sizeof(dir_ent_t));
            cur_dir = next_dir;
            cur_off_in_block = 0;            
            continue;
        }
        next_dir += 1;
        memcpy(cur_dir, next_dir, sizeof(dir_ent_t));
        cur_dir += 1;
        cur_off_in_block += 1;
    }
    // set size
    inode_p->size -= sizeof(dir_ent_t);
    // check if direct field need to -1
    unsigned int blk_need = inode_p->size / 4096 + 1;
    unsigned int blk_used;
    for(blk_used = 0; i < DIRECT_PTRS; i++){
        if(inode_p->direct[blk_used] == -1){
            break;
        }
    }
    if(blk_used > blk_need){
        unsigned int blk = inode_p->direct[blk_used - 1];
        set_bit(dbm_addr, blk - super->data_region_addr);
        inode_p->direct[blk_used - 1] = -1;
    }
    // synchronize
    if(msync(start, img_sz, MS_SYNC) == -1){
        server_Error(&reply);
        return -1;
    }
    // send packet
    reply.inum = inode_c->inum;
    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
    return 0;

}
int server_Shutdown(){
    MFS_Msg_t reply;
    reply.msg_type = MFS_SHUTDOWN;
    if(msync(start, img_sz, MS_SYNC) == -1){
        char message[] = "Shutdown failed: msync() failed!";
        strcpy(reply.buf, message);
        server_Error(&reply);
        return -1;
    }
    if(munmap(start, img_sz, MS_SYNC) == -1){
        char message[] = "Shutdown failed: munmap() failed!";
        strcpy(reply.buf, message);
        server_Error(&reply);
        return -1;
    }
    exit(0);
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
        // here
        if(rc < 0) continue;

        printf("server:: read message [size:%d contents:(%s)]\n", rc, (char*)&msg);
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
                MFS_Msg_t rs;
                rs.msg_type = MFS_ERROR;
                server_Error(&rs);
                break;
        }
    }
    return 0; 
}
