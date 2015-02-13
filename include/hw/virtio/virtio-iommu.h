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

#ifndef _QEMU_VIRTIO_IOMMU_H
#define _QEMU_VIRTIO_IOMMU_H

#include "hw/virtio/virtio.h"
#include "hw/block/block.h"
#include "sysemu/iothread.h"
#include "block/block.h"

#define TYPE_VIRTIO_IOMMU "virtio-iommu-device"
#define VIRTIO_IOMMU(obj) \
        OBJECT_CHECK(VirtIOIommu, (obj), TYPE_VIRTIO_IOMMU)

/* The ID for virtio_block */
#define VIRTIO_ID_IOMMU 14

struct virtio_iommu_config
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
#define VIRTIO_IOMMU_T_IN         0
#define VIRTIO_IOMMU_T_OUT        1

/* return the device ID string */
#define VIRTIO_BLK_T_GET_ID     8

struct virtio_iommu_outhdr
{
    uint32_t cmd;
};

#define VIRTIO_IOMMU_S_OK         0
#define VIRTIO_IOMMU_S_IOERR      1
#define VIRTIO_IOMMU_S_UNSUPP     2

/* This is the last element of the write scatter-gather list */
struct virtio_iommu_inhdr
{
    unsigned char status;
};

struct virtio_iommu_out_param {
    void *data;
    int  len;
};

typedef struct VirtIOIommuConf
{
    IOThread *iothread;
} VirtIOIommuConf;

struct VirtIOIommuReq;
typedef struct VirtIOIommu {
    VirtIODevice parent_obj;
    VirtQueue *vq;
    void *rq;
    QEMUBH *bh;
    VirtIOIommuConf iommu;
    VMChangeStateEntry *change;
    void (*complete_request)(struct VirtIOIommuReq *req, unsigned char status);
} VirtIOIommu;

typedef struct VirtIOIommuReq {
    VirtIOIommu *dev;
    VirtQueueElement elem;
    struct virtio_iommu_inhdr *in;
    struct iovec param; 
    struct virtio_iommu_outhdr out;
    QEMUIOVector qiov;
    struct VirtIOKFDReq *next;
} VirtIOIommuReq;

VirtIOIommuReq *virtio_iommu_alloc_request(VirtIOIommu *s);

void virtio_iommu_free_request(VirtIOIommuReq *req);

#endif
