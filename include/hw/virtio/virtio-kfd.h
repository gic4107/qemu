/*
 * Virtio Block Device
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _QEMU_VIRTIO_KFD_H
#define _QEMU_VIRTIO_KFD_H

#include "hw/virtio/virtio.h"
#include "hw/block/block.h"
#include "sysemu/iothread.h"
#include "block/block.h"

#define TYPE_VIRTIO_KFD "virtio-kfd-device"
#define VIRTIO_KFD(obj) \
        OBJECT_CHECK(VirtIOKfd, (obj), TYPE_VIRTIO_KFD)

/* from Linux's linux/virtio_blk.h */

/* The ID for virtio_block */
#define VIRTIO_ID_KFD 13

/* Feature bits */
//#define VIRTIO_BLK_F_BARRIER    0       /* Does host support barriers? */

struct virtio_kfd_config
{
    uint64_t capacity;
    uint32_t size_max;
    uint32_t seg_max;
    uint16_t cylinders;
    uint8_t heads;
    uint8_t sectors;
    uint32_t blk_size;
    uint8_t physical_block_exp;
    uint8_t alignment_offset;
    uint16_t min_io_size;
    uint32_t opt_io_size;
    uint8_t wce;
} QEMU_PACKED;


/* These two define direction. */
#define VIRTIO_KFD_T_IN         0
#define VIRTIO_KFD_T_OUT        1

/* return the device ID string */
#define VIRTIO_BLK_T_GET_ID     8

struct virtio_kfd_outhdr
{
    uint32_t cmd;
    uint64_t vm_mm;
};

#define VIRTIO_KFD_S_OK         0
#define VIRTIO_KFD_S_IOERR      1
#define VIRTIO_KFD_S_UNSUPP     2

/* This is the last element of the write scatter-gather list */
struct virtio_kfd_inhdr
{
    unsigned char status;
};

struct virtio_kfd_out_param {
    void *data;
    int  len;
};

typedef struct VirtIOKfdConf
{
//    BlockConf conf;
    IOThread *iothread;
//    char *serial;
} VirtIOKfdConf;

struct VirtIOKfdReq;
typedef struct VirtIOKfd {
    VirtIODevice parent_obj;
//    CharDriverState *cs;
    VirtQueue *vq;
    void *rq;
    QEMUBH *bh;
//    BlockConf *conf;
    VirtIOKfdConf kfd;
//    unsigned short sector_mask;
//    bool original_wce;
    VMChangeStateEntry *change;
    /* Function to push to vq and notify guest */
    void (*complete_request)(struct VirtIOKfdReq *req, unsigned char status);
} VirtIOKfd;

typedef struct VirtIOKfdReq {
    VirtIOKfd *dev;
    VirtQueueElement elem;
    struct virtio_kfd_inhdr *in;
    struct iovec param; 
    struct virtio_kfd_outhdr out;
    QEMUIOVector qiov;
    struct VirtIOKFDReq *next;
//    BlockAcctCookie acct;
} VirtIOKfdReq;

VirtIOKfdReq *virtio_kfd_alloc_request(VirtIOKfd *s);

void virtio_kfd_free_request(VirtIOKfdReq *req);

#endif
