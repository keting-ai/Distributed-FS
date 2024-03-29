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

unsigned long get_bit(unsigned long *bitmap, int position) {
   int index = position / 32;
   int offset = 31 - (position % 32);
   return (bitmap[index] >> offset) & 0x1;
}

void set_bit(unsigned long *bitmap, int position) {
   int index = position / 32;
   int offset = 31 - (position % 32);
   bitmap[index] |= 0x1 << offset;
}

int server_Error(MFS_Msg_t* reply){
    reply->msg_type = MFS_ERROR;
    reply->inum = -1;
    UDP_Write(sd, &caddr, (char*)(void*)reply, sizeof(MFS_Msg_t));
    return 0;
}

int server_Stat(int inum){
    //fprintf(stderr, "DEBUG server Stat start\n");
    MFS_Msg_t reply;
    reply.msg_type = MFS_STAT;
    unsigned long inode_bit = get_bit(inbm_addr, inum);
    if(!inode_bit){
        server_Error(&reply);
        return -1;
    }
    inode_t* inode = inrg_addr + inum * sizeof(inode_t);
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
    //fprintf(stderr, "DEBUG server lookup:: pinum: %d\n", pinum);
    void* rc_err = (void*)(unsigned long)-1;
    unsigned long inode_bit = get_bit(inbm_addr, pinum);
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
    //fprintf(stderr, "DEBUG server lookup:: entry_num: %d, size: %d\n", entry_num, size);
    int num_block = size / (UFS_BLOCK_SIZE + 1) + 1;
    int data_blocks[num_block]; // stores the blocks' addr (in blocks)
    dir_ent_t* entries[entry_num];
    for(int i = 0; i < num_block; i++){
        data_blocks[i] = inode->direct[i];
    }
    // fill in the entries
    int remain_entry = entry_num;
    for(int i = 0; i < num_block; i++){
        int data_block = data_blocks[i];
        //fprintf(stderr, "DEBUG server lookup:: data_block: %d\n", data_block);
        unsigned long data_addr = data_block * UFS_BLOCK_SIZE; // relative address
        /*
        if(!get_bit(dbm_addr, data_block - super->data_region_addr)){
            //fprintf(stderr, "DEBUG server lookup err1\n");
            return rc_err;
        }
        */
        unsigned long loopend;
        if(remain_entry < UFS_BLOCK_SIZE / sizeof(dir_ent_t)){
            loopend = remain_entry;
        }else{
            loopend = UFS_BLOCK_SIZE / sizeof(dir_ent_t);
        }
        void* data_ptr = (void*)((unsigned long)data_addr + (unsigned long)start); // real address
        for(int j = 0; j < loopend; j++){
            entries[j + (UFS_BLOCK_SIZE / sizeof(dir_ent_t)) * i] = (dir_ent_t*)data_ptr;
            remain_entry--;
            data_ptr = (void*)data_ptr; // real address
            data_ptr += sizeof(dir_ent_t);
        }
    }

    // compare entries' names with name
	//fprintf(stderr, "DEBUG: entry_num: %d\n", entry_num);
    for(int i = 0; i < entry_num; i++){
        ////fprintf(stderr, "DEBUG lookup:: name: %s\n", entries[i]->name);
        if(!strcmp(name, entries[i]->name)){
            //fprintf(stderr, "DEBUG: found: name: %s\n", entries[i]->name);
            // found
            return (void*)entries[i];
        }
    }
    // not found
    void* rc_notfound = (void*)(unsigned long)-2;
    return rc_notfound;
}

int server_Lookup(int pinum, char* name){
    //fprintf(stderr, "DEBUG server Lookup start\n");
    MFS_Msg_t reply;
    reply.msg_type = MFS_LOOKUP;
    void* ptr = lookup(pinum, name);
    if((unsigned long)ptr == -1 || -(unsigned long)ptr == 2){
        server_Error(&reply);
        return -1;
    }
    reply.inum = ((dir_ent_t*)ptr)->inum;
    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
    return 0;
}

int server_Write(int inum, char *buffer, int offset, int nbytes){
    ////fprintf(stderr, "DEBUG server write start\n");
    MFS_Msg_t reply;
    reply.msg_type = MFS_WRITE;
    if(nbytes > MFS_BUFFER || !get_bit(inbm_addr, inum)){
    //fprintf(stderr, "DEBUG server write err1\n");
        server_Error(&reply);
        return -1;
    }
    inode_t* inode = inrg_addr + inum * sizeof(inode_t);
    int size = inode->size;
    int type = inode->type;
    ////fprintf(stderr, "DEBUG server:: inum: %d, size: %d, type: %d, offset: %d\n", inum, size, type, offset);
    if(offset > size || type == MFS_DIRECTORY){
        //fprintf(stderr, "DEBUG server write err2\n");
        server_Error(&reply);
        return -1;
    }
    // find the start location of offset to write
    int start_blk = offset / 4096;
    int start_off = offset % 4096;
    int remain_bytes = nbytes;
    int blk_write_off = start_off;
    int buffer_off = 0;
    int this_block = inode->direct[start_blk]; // current writing block (in blocks)
    /*
    for(int i = 0; i < 30; i++){
        //fprintf(stderr, "inode->direct[%d]: %d\n", i, inode->direct[i]);
    }
    */
    if(this_block < 0){
        // get a new block
        unsigned int newblk = 0;
        for(int i = 0; i < super->num_data; i++){
            if(!get_bit(dbm_addr, i)){
                newblk = i + super->data_region_addr;
                set_bit(dbm_addr, i);
                this_block = newblk;
                break;
            }
        }
        if(newblk == 0){
            server_Error(&reply);
            return -1;
        }
    }
    inode->direct[start_blk] = this_block;

    //fprintf(stderr, "DEBUG server:: inum: %d, start_block: %d, this_block: %d\n", inum, start_blk, this_block);
    if(!get_bit(dbm_addr, this_block - super->data_region_addr)){ // if this block is unused
        ////fprintf(stderr, "DEBUG server:: diff:%ld\n", this_block - super->data_region_addr);
        //fprintf(stderr, "DEBUG server write err3\n");
        server_Error(&reply);
        return -1;
    }
    unsigned long this_block_addr = this_block * UFS_BLOCK_SIZE; // relative addr
    unsigned long cur_write_addr = this_block_addr + start_off; // relative addr

    // write until this block is full
    // to another block(if there's following block, use that, otherwise use an unused)
    int i = 0;
    unsigned long write_addrs[nbytes]; // stores real addrs
    unsigned long data_block_use = -1; // extra data block number to use 
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
        *(char*)(void*)(unsigned long)(write_addrs[i] + (unsigned long)start) = *(buffer + i); // real address
        ////fprintf(stderr, "DEBUG server write::%c\n", *(buffer+i));
    }
    set_bit(dbm_addr, data_block_use);
    // update inode
    inode->size += nbytes;
    for(int i = 0; i < DIRECT_PTRS; i++){
        if(inode->direct[i] == -1){
            if(data_block_use != -1){
                inode->direct[i] = data_block_use + super->data_region_addr;
            }
            break;
        }
    }
    // synchronize to disk
    if(msync(start, img_sz, MS_SYNC) == -1){
        //fprintf(stderr, "DEBUG server write msync err\n");
        server_Error(&reply);
        return -1;
    }
    // reply
    reply.inum = inum;
    //fprintf(stderr, "DEBUG server write:: inum: %d\n", inum);
    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
    return 0;
}

int server_Read(int inum, char *buffer, int offset, int nbytes){
    //fprintf(stderr, "DEBUG server read start\n");
	MFS_Msg_t reply;
    reply.msg_type = MFS_READ;
    unsigned long inode_bit = get_bit(inbm_addr, inum);
    //fprintf(stderr, "DEBUG server read:: nbytes: %d\n", nbytes);
    if(!inode_bit || nbytes > MFS_BUFFER || sizeof(buffer) > MFS_BLOCK_SIZE){
        //fprintf(stderr, "DEBUG server read err1\n");
        server_Error(&reply);
        return -1;
    }
	inode_t* inode = inrg_addr + inum * sizeof(inode_t);
    int size = inode->size;
    int type = inode->type;
    if(offset >= size){
        //fprintf(stderr, "DEBUG server read err2\n");
        server_Error(&reply);
        return -1;
    }
    if(type != MFS_REGULAR_FILE && type != MFS_DIRECTORY){
        //fprintf(stderr, "DEBUG server read err3\n");
        server_Error(&reply);
        return -1;
    }
    // find the start location of offset to read
    int start_blk = offset / 4096;
    int start_off = offset % 4096;
    int remain_bytes = nbytes;
    int blk_read_off = start_off;
    int buffer_off = 0;
    unsigned long this_block = inode->direct[start_blk]; // in blocks current writing block
    unsigned long this_block_addr = this_block * UFS_BLOCK_SIZE;
    unsigned long cur_read_addr = this_block_addr + start_off;

    // Directory case: cannot read if it doesn't read from start of each entry
    if(type == MFS_DIRECTORY && start_off % 32 != 0){
        //fprintf(stderr, "DEBUG server read err4\n");
        server_Error(&reply);
        return -1;
    }

    // read until this block is full
    // to another block(if there's following block, use that, otherwise use a unused)
    //fprintf(stderr, "DEBUG server read:: remain_bytes: %d\n", remain_bytes);
    int i = 0;
    while(remain_bytes > 0){
        if(blk_read_off < 4096){
            *(buffer + buffer_off) = *(char*)(void*)(unsigned long)(cur_read_addr + (unsigned long)start); //TODO: check this
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
                //fprintf(stderr, "DEBUG server read err5\n");
                server_Error(&reply);
                return -1;
            }
        }
    }
    reply.inum = inum;
    
    ////fprintf(stderr, "DEBUG server buffer:\n");
    for(int i = 0; i < nbytes; i++){
        ////fprintf(stderr, "%c", *(buffer+i));
        reply.buf[i] = *(buffer+i);
    }
    ////fprintf(stderr, "\n");
    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
    return 0;
}

int get_free_inum(){
    for(int i = 0; i < super->num_inodes; i++){
        int bit = get_bit(inbm_addr, i);
        if(bit == 0) return i;
    }
    return -1;
}

int get_free_datanum(){
    for(int i = 0; i < super->num_data; i++){
        int bit = get_bit(dbm_addr, i);
        if(bit == 0) return i;
    }
    return -1;
}

int server_Creat(int pinum, int type, char *name){
	//fprintf(stderr, "DEBUG server:: creat\n");
    // remember to include \0 at the end of dir_ent_t's name field!
    MFS_Msg_t reply;
    reply.msg_type = MFS_CREAT;
    unsigned long inode_bit = get_bit(inbm_addr, pinum);
    // pinum does not exist
    if(!inode_bit){
        server_Error(&reply);
        return -1;
    }
    if(strlen(name) > 28){
        server_Error(&reply);
        return -1;
    }
    // check if name already exist

    void* ptr = lookup(pinum, name);
	//fprintf(stderr, "DEBUG server:: creat1\n");
    if((unsigned long)ptr == -1){
        server_Error(&reply);
        return -1;
    }
    if((unsigned long)ptr != -2){
        reply.inum = ((dir_ent_t*)ptr)->inum;
        UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
        return 0;
    }
    inode_t* inode_p = inrg_addr + pinum * sizeof(inode_t);
    //int p_size = inode_p->size;
    int p_type = inode_p->type;
    // error if it's not the parent directory
    if(p_type != MFS_DIRECTORY){
        server_Error(&reply);
        return -1;
    }

    // find place to add the new directory entry 
    int block_idx = 0;
    while((int)inode_p->direct[block_idx] != -1){
        block_idx++;
    }
    block_idx--; // the last valid block index
    int remain_entry = (inode_p->size % (UFS_BLOCK_SIZE + 1)) / sizeof(dir_ent_t); // calculate the remain entries
    //fprintf(stderr, "DEBUG server:: size: %d, remain_entry: %d, block_idx: %d\n", inode_p->size, remain_entry, block_idx);
    unsigned long dir_block = inode_p->direct[block_idx]; // in blocks current writing block
    unsigned long block_addr = dir_block * UFS_BLOCK_SIZE;

    dir_ent_t* entries[remain_entry];
    void* dir_block_addr = (void*)((unsigned long)block_addr + (unsigned long)start); // real address
    int j;
    for(j = 0; j < remain_entry; j++){
        entries[j] = (dir_ent_t*)dir_block_addr;
        dir_block_addr = (void*)dir_block_addr; // real address
        dir_block_addr += sizeof(dir_ent_t);
    }
    j -= 1;
    entries[remain_entry] = (dir_ent_t*)dir_block_addr;

    // if the last block is not full
    if(sizeof(entries) < (4096-32)){
		//fprintf(stderr, "DEBUG server:: creat j: %d\n", j);
        strcpy(entries[remain_entry]->name, name); //FIXME: 不知道能不能直接用entries
        //fprintf(stderr, "DEBUG server:: entries[remain_entry]->name: %s\n", entries[remain_entry]->name);
        entries[remain_entry]->inum = get_free_inum();
        //set_bit(inbm_addr, get_free_inum());
    }
    // if full, find another
    if(sizeof(entries) >= (4096-32)){
        // find the following block
        unsigned long new_block;
        unsigned long new_block_addr;
        int has_place = 0;
        int k;
        for(k = 0; k < super->num_data; k++){
            if(get_bit(dbm_addr, j)) continue; // jth data block is used, continue find
            // use jth data block
            new_block = k + super->data_region_addr;
            new_block_addr = new_block * UFS_BLOCK_SIZE;
            break;                   
        }
        // no place remaining!
        if(!has_place){
            server_Error(&reply);
            return -1;
        }
        entries[remain_entry] = (dir_ent_t*)(void*)(unsigned long)new_block_addr;
        strcpy(entries[k+1]->name, name);
        entries[remain_entry]->inum = get_free_inum();
        set_bit(inbm_addr, get_free_inum());
    }
    // set size of parent directory
    inode_p->size += sizeof(dir_ent_t);
    // if create regular file ...
    int inode_num;
    if(type == MFS_REGULAR_FILE){
        // add new inode
        inode_num = get_free_inum();
        //fprintf(stderr, "DEBUG server creat:: inode_num: %d\n", inode_num);
        inode_t* new_inode = inrg_addr + inode_num * sizeof(inode_t);
        // type
        new_inode->type = MFS_REGULAR_FILE;
        // size
        new_inode->size = 0;
        //int data_num = get_free_datanum();
        //unsigned long data_addr = (unsigned long)(super->data_region_addr + data_num); // TODO: Check this
        ////fprintf(stderr, "DEBUG server creat:: data_num: %d, data_addr: %ld\n", data_num, data_addr);
        // dir
        //new_inode->direct[0] = data_addr;
        for(int i = 0; i < 30; i++){
            new_inode->direct[i] = -1;
        }
        // update inode and data bitmap
        set_bit(inbm_addr, inode_num);
        //set_bit(dbm_addr, data_num);
    }
    // if create directory file ...
    if(type == MFS_DIRECTORY){
        // add new inode
        inode_num = get_free_inum();
        inode_t* new_inode = inrg_addr + inode_num * sizeof(inode_t);

        // type
        new_inode->type = MFS_DIRECTORY;

        // size -> 64: write in contains . and ..
        new_inode->size = sizeof(dir_ent_t)*2;
        int data_num = get_free_datanum();
        void* data_addr_ptr = (void*)(unsigned long)(drg_addr + data_num * MFS_BLOCK_SIZE); // TODO: Check this
        // write in . and .. in data region
        dir_ent_t* entry1 = (dir_ent_t*)data_addr_ptr;
        entry1->inum = get_free_inum();
        strcpy(entry1->name, ".");
        void* data_addr_ptr2 = (void*)(unsigned long)(drg_addr + data_num * MFS_BLOCK_SIZE + sizeof(dir_ent_t)); // TODO: Check this
        dir_ent_t* entry2 = (dir_ent_t*)data_addr_ptr2;
        entry2->inum = pinum;
        strcpy(entry2->name, "..");

        // dir
        new_inode->direct[0] = data_num + super->data_region_addr;
        for(int i = 1; i < 30; i++){
            new_inode->direct[i] = -1;
        }
        // update inode and data bitmap
        set_bit(inbm_addr, inode_num);
        set_bit(dbm_addr, data_num);
    }
    // synchronize
    if(msync(start, img_sz, MS_SYNC) == -1){
        server_Error(&reply);
        return -1;
    }
    // send packet
    reply.inum = inode_num;
    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
    return 0;
}

int server_Unlink(int pinum, char *name){
    //fprintf(stderr, "DEBUG server unlink start\n");
    MFS_Msg_t reply;
    reply.msg_type = MFS_UNLINK;
    void* dir_entry = lookup(pinum, name);
    if((unsigned long)dir_entry == -1 || (unsigned long)dir_entry == -2){
        server_Error(&reply);
        return -1;
    }
    int rp_inum = ((dir_ent_t*)dir_entry)->inum;
    int inum = ((dir_ent_t*)dir_entry)->inum;
    if(!get_bit(inbm_addr, inum)){
        server_Error(&reply);
        return -1;
    }
    inode_t* inode_p = inrg_addr + pinum * sizeof(inode_t);
    inode_t* inode_c = inrg_addr + inum * sizeof(inode_t);
    //int size = inode_c->size;
    if(inode_c->type == UFS_DIRECTORY && inode_c->size != sizeof(dir_ent_t) * 2){
        // check if its void
        server_Error(&reply);
        return -1;
    }
    // unlink
    // set this inode bitmap to zero
    set_bit(inbm_addr, inum);
    // set this data bitmap to zero
    //fprintf(stderr, "DEBUG server unlink here1\n");
    int i = 0;
    while(inode_c->direct[i] != -1){
        int data_blk = inode_c->direct[i];
        //fprintf(stderr, "DEBUG server unlink data_blk: %d\n", data_blk);
        set_bit(dbm_addr, data_blk - super->data_region_addr);
        i++;
    }
    // shift back a dir_ent_t in parent directory
    dir_ent_t* cur_dir = (dir_ent_t*)dir_entry;
    dir_ent_t* next_dir = cur_dir;
    unsigned long start_dir_addr = (unsigned long)(void*)cur_dir - (unsigned long)start; // relative address
    unsigned long start_dir_block = start_dir_addr / 4096; // the start editing block number
    unsigned long nth_block; // the nth block in parent directory file
    for(int i = 0; i < DIRECT_PTRS; i++){
        if(inode_p->direct[i] == start_dir_block){
            nth_block = i;
            break;
        }
    }
    //unsigned long start_file_addr = inode_p->direct[0] * 4096; // the starting relative file addr
    int size_diff  = start_dir_addr % 4096 + nth_block * 4096;
    int size_remain = inode_p->size - size_diff;
    int cur_off_in_block = start_dir_addr % 4096 / sizeof(dir_ent_t); // current offset(in dir_ent_t) in one block
    int cur_block = nth_block;
    //fprintf(stderr, "DEBUG server unlink size_remain: %d, size_diff: %d\n", size_remain, size_diff);
    // one block has 0-127th dir_ent_t
    for(int i = 1; i < size_remain / sizeof(dir_ent_t); i += 1){
        if(cur_off_in_block == 127){ // the last dir_ent_t in one block
            // copy from the first dir_ent_t in the next block
            // then set cur_off_in_block to 0
            // set the cur_dir, next_dir to the first in the next block
            cur_block += 1;
            next_dir = (dir_ent_t*)(unsigned long)inode_p->direct[cur_block];
            if((long int)next_dir == -1){
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
    //fprintf(stderr, "DEBUG server unlink here3\n");
    inode_p->size -= sizeof(dir_ent_t);
    // check if direct field need to -1
    unsigned long blk_need = inode_p->size / 4096 + 1;
    unsigned long blk_used;
    for(blk_used = 0; i < DIRECT_PTRS; i++){
        if(inode_p->direct[blk_used] == -1){
            break;
        }
    }
    if(blk_used > blk_need){
        unsigned long blk = inode_p->direct[blk_used - 1];
        set_bit(dbm_addr, blk - super->data_region_addr);
        inode_p->direct[blk_used - 1] = -1;
    }
    // synchronize
    if(msync(start, img_sz, MS_SYNC) == -1){
        server_Error(&reply);
        return -1;
    }
    // send packet
    reply.inum = rp_inum;
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
    if(munmap(start, img_sz) == -1){
        char message[] = "Shutdown failed: munmap() failed!";
        strcpy(reply.buf, message);
        server_Error(&reply);
        return -1;
    }

    UDP_Write(sd, &caddr, (char*)&reply, sizeof(MFS_Msg_t));
    return 0;
}

void intHandler(int dummy) {
        UDP_Close(sd);
        exit(130);
}
// server code
int main(int argc, char *argv[]) {
	//fprintf(stderr, "server:: init\n");
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
        int rc = UDP_Read(sd, &caddr, (char*)&msg, sizeof(MFS_Msg_t));
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
                /*
                for(int i = 0; i < msg.nbytes; i++){
                    //fprintf(stderr, "%c", msg.buf[i]);
                }
                //fprintf(stderr, "\n");*/
                server_Write(msg.inum, (char*)msg.buf, msg.offset, msg.nbytes);
                break;
            case MFS_READ:
                server_Read(msg.inum, (char*)msg.buf, msg.offset, msg.nbytes);
                break;
            case MFS_CREAT:
				//fprintf(stderr, "DEBUG: Creat\n");
                server_Creat(msg.inum, msg.creat_type, (char*)msg.buf);
                break;
            case MFS_UNLINK:
                server_Unlink(msg.inum, (char*)msg.buf);
                break;
            case MFS_SHUTDOWN:
                int ret = server_Shutdown();
				if(ret == 0) exit(0);
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
