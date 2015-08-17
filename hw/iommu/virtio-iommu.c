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

#include "qemu-common.h"
#include "qemu/iov.h"
#include "qemu/error-report.h"
#include "trace.h"
#include "hw/virtio/virtio-iommu.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-access.h"
#include "hw/virtio/virtio-pci.h"
#include "virtio-iommu.h"

#include <linux/iommu_vm_ppr_ioctl.h>
#include <linux/virtio_ids.h>
#include <sys/mman.h>
#include <fcntl.h>

#define IOMMU_VM_PPR_DEVICE "/dev/iommu-vm-ppr"
static int iommu_vm_ppr_fd;
static struct iommu_back_end iommu_be;

VirtIOIommuReq *virtio_iommu_alloc_request(VirtIOIommu *s)
{
    VirtIOIommuReq *req = g_slice_new(VirtIOIommuReq);
    req->dev = s;
    req->qiov.size = 0;
    req->next = NULL;
    return req;
}

void virtio_iommu_free_request(VirtIOIommuReq *req)
{
    if (req) {
        g_slice_free(VirtIOIommuReq, req);
    }
}

static void virtio_iommu_complete_request(VirtIOIommuReq *req,
                                        unsigned char status)
{
    VirtIOIommu *s = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    printf("virtio_iommu_complete_request, status=%d\n", status);

    stb_p(&req->in->status, status);
    virtqueue_push(s->vq, &req->elem, req->qiov.size + sizeof(*req->in));
    virtio_notify(vdev, s->vq);
}

static void virtio_iommu_req_complete(VirtIOIommuReq *req, unsigned char status)
{
    req->dev->complete_request(req, status);
}

static VirtIOIommuReq *virtio_iommu_get_request(VirtIOIommu *s)
{
    VirtIOIommuReq *req = virtio_iommu_alloc_request(s);

    if (!virtqueue_pop(s->vq, &req->elem)) {
        virtio_iommu_free_request(req);
        return NULL;
    }

    return req;
}

static int 
virtio_iommu_mmap_ppr_region(struct iovec *ppr_region)
{
    uint64_t vm_ppr_region_gpa;
    void *vm_ppr_region_hva;    
    size_t vm_ppr_region_size = VM_PPR_REGION_SIZE;
    int i;

    printf("virtio_iommu_mmap_ppr_region\n");

    // get vm_mm from front-end
    iov_to_buf(ppr_region, 1, 0, &vm_ppr_region_gpa, sizeof(vm_ppr_region_gpa));

    vm_ppr_region_hva = cpu_physical_memory_map(vm_ppr_region_gpa, &vm_ppr_region_size, 1);
    if(vm_ppr_region_size != VM_PPR_REGION_SIZE) {
        fprintf(stderr, "!!! ppr region mapped size not equal to 4096\n");
        goto fault_unmmap;
    }

    // mmap to host iommu-vm-ppr
    printf("vm_ppr_region_hva=%llx\n", vm_ppr_region_hva);
    void *ptr = mmap(vm_ppr_region_hva, VM_PPR_REGION_SIZE, 
                PROT_WRITE|PROT_READ, MAP_SHARED|MAP_FIXED, iommu_vm_ppr_fd, 0);
    if(ptr == MAP_FAILED) {
        printf("mmap fail\n");                                                       
        goto fault_unmmap;
    }
    else                                                                             
        printf("mmap succ %p %p\n", vm_ppr_region_hva, ptr);  

    return 1;

fault_mmap:
    munmap(vm_ppr_region_hva, VM_PPR_REGION_SIZE);
fault_unmmap:
    cpu_physical_memory_unmap(vm_ppr_region_hva, vm_ppr_region_size, 1,
                                                         vm_ppr_region_size); 
    return -EFAULT;
}

void virtio_iommu_handle_request(VirtIOIommuReq *req)
{
    uint32_t type;
    struct iovec *in_iov = req->elem.in_sg;
    struct iovec *iov = req->elem.out_sg;
    unsigned in_num = req->elem.in_num;
    unsigned out_num = req->elem.out_num;
    struct vm_mmu_notification mmu;
    int status = VIRTIO_IOMMU_S_OK; 
    int head;
    int ret = 0;

    if (req->elem.out_num < 1 || req->elem.in_num < 1) {
        error_report("virtio-iommu missing headers");
        exit(1);
    }

/*    if (unlikely(iov_to_buf(iov, out_num, 0, &req->out,         // copy vring data into req->out
                            sizeof(req->out)) != sizeof(req->out))) {
        error_report("virtio-iommu request outhdr too short");
        exit(1);
    }
*/
    iov_to_buf(&iov[0], 1, 0, &req->out.cmd, sizeof(int));
    printf("virtio_iommu_handle_request: command=%d\n", req->out.cmd); 
     

//    iov_discard_front(&iov, &out_num, sizeof(req->out));

    if (in_num < 1 ||
        in_iov[in_num - 1].iov_len < sizeof(struct virtio_iommu_inhdr)) {
        error_report("virtio-iommu request inhdr too short");
        exit(1);
    }

    if (in_num == 1)    // no param
        req->in = in_iov[0].iov_base + in_iov[0].iov_len - sizeof(struct virtio_iommu_inhdr);
    else {
        req->param = in_iov[0];                         // param
        req->in = (void *)in_iov[in_num - 1].iov_base   // status
                  + in_iov[in_num - 1].iov_len
                  - sizeof(struct virtio_iommu_inhdr);
    }
//    iov_discard_back(in_iov, &in_num, sizeof(struct virtio_iommu_inhdr));

    switch(req->out.cmd) {
    case VIRTIO_IOMMU_MMAP_PPR_REGION:
        printf("VIRTIO_IOMMU_MMAP_PPR_REGION\n");
        ret = virtio_iommu_mmap_ppr_region(&req->param);
        if(ret == -1) {
            printf("!!! virtio_iommu_mmap_ppr_region fail, %d\n", ret);
            status = VIRTIO_IOMMU_S_IOERR;
        }
        break;

    case VIRTIO_IOMMU_VM_FINISH_PPR:
        iov_to_buf(&req->param, 1, 0, &head, sizeof(head));
        ret = ioctl(iommu_vm_ppr_fd, IVP_IOC_VM_FINISH_PPR, &head);
        if (ret < 0) {
            printf("!!! VIRTIO_IOMMU_VM_FINISH_PPR fail, %d\n", ret);
            status = VIRTIO_IOMMU_S_IOERR;
        }
        break;

    case VIRTIO_IOMMU_CLEAR_FLUSH_YOUNG:
        printf("VIRTIO_IOMMU_CLEAR_FLUSH_YOUNG\n");
        iov_to_buf(&req->param, 1, 0, &mmu, sizeof(mmu));
        printf("mm=0x%llx, addr=0x%llx\n", mmu.mm, mmu.start);
        ret = ioctl(iommu_vm_ppr_fd, IVP_IOC_MMU_CLEAR_FLUSH_YOUNG, &mmu);
        if (ret < 0) {
            printf("!!! VIRTIO_IOMMU_CLEAR_FLUSH_YOUNG fail, %d\n", ret);
            status = VIRTIO_IOMMU_S_IOERR;
        }
        break;

    case VIRTIO_IOMMU_CHANGE_PTE:
        printf("VIRTIO_IOMMU_CHANGE_PTE\n");
        iov_to_buf(&req->param, 1, 0, &mmu, sizeof(mmu));
        printf("mm=0x%llx, addr=0x%llx\n", mmu.mm, mmu.start);
        ret = ioctl(iommu_vm_ppr_fd, IVP_IOC_MMU_CHANGE_PTE, &mmu);
        if (ret < 0) {
            printf("!!! VIRTIO_IOMMU_CHANGE_PTE fail, %d\n", ret);
            status = VIRTIO_IOMMU_S_IOERR;
        }
        break;

    case VIRTIO_IOMMU_INVALIDATE_RANGE_START:
        printf("VIRTIO_IOMMU_INVALIDATE_RANGE_START\n");
        iov_to_buf(&req->param, 1, 0, &mmu, sizeof(mmu));
        printf("mm=0x%llx, start=0x%llx, end=0x%llx\n", mmu.mm, mmu.start, mmu.end);
        ret = ioctl(iommu_vm_ppr_fd, IVP_IOC_MMU_INVALIDATE_RANGE_START, &mmu);
        if (ret < 0) {
            printf("!!! VIRTIO_IOMMU_INVALIDATE_RANGE_START fail, %d\n", ret);
            status = VIRTIO_IOMMU_S_IOERR;
        }
        break;

    default:
        printf("Known command\n");
        status = VIRTIO_IOMMU_S_UNSUPP;
    }

    virtio_iommu_req_complete(req, status);
    virtio_iommu_free_request(req);
}

static void virtio_iommu_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOIommu *s = VIRTIO_IOMMU(vdev);
    VirtIOIommuReq *req;

//    printf("virtio_iommu_handle_output\n");

    while ((req = virtio_iommu_get_request(s))) { // get one request (separator: next flag)
        virtio_iommu_handle_request(req);
    }

    /*
     * FIXME: Want to check for completions before returning to guest mode,
     * so cached reads and writes are reported as quickly as possible. But
     * that should be done in the generic block layer.
     */
}

static void virtio_iommu_reset(VirtIODevice *vdev)
{
    VirtIOIommu *s = VIRTIO_IOMMU(vdev);

    printf("virtio_iommu_reset\n");
}

static void virtio_iommu_update_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOIommu *s = VIRTIO_IOMMU(vdev);
    struct virtio_iommu_config cfg;
    uint64_t capacity;

    printf("virtio_iommu_update_config\n");
}

static void virtio_iommu_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VirtIOIommu *s = VIRTIO_IOMMU(vdev);
    struct virtio_iommu_config cfg;

    printf("virtio_iommu_set_config\n");
}

static uint32_t virtio_iommu_get_features(VirtIODevice *vdev, uint32_t features)
{
    VirtIOIommu *s = VIRTIO_IOMMU(vdev);

    printf("virtio_iommu_get_features\n");

    return features;
}

static void virtio_iommu_set_status(VirtIODevice *vdev, uint8_t status)
{
    VirtIOIommu *s = VIRTIO_IOMMU(vdev);
    DeviceState *dev = &vdev->parent_obj;
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    EventNotifier *n;
    static eventfd_init = 0;
    uint32_t features;
    int fd;
    int r;

    if (!(status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        return;
    }

    if (!eventfd_init) {
        eventfd_init = 1;
        printf("setup irqfd and eventfd\n");
        // bind KVM_IRQFD
        if (!k->set_guest_notifiers) 
            printf("!!!binding does not support guest notifiers");
    
        r = k->set_guest_notifiers(qbus->parent, 1, true);
        if (r < 0) 
            printf("Error binding guest notifier: %d", r);

        // bind eventfd to iommu-vm-ppr
        n = virtio_queue_get_guest_notifier(vdev->vq);
        fd = event_notifier_get_fd(n);
        printf("set eventfd: fd=%d\n", fd);

        if (ioctl(iommu_vm_ppr_fd, IVP_IOC_SET_KVM_EVENTFD, &fd) <0) 
            printf("IVP_IOC_SET_KVM_EVENTFD fail!!!\n"); 
        printf("IVP_IOC_SET_KVM_EVENTFD succeed!!!\n"); 
    }

    features = vdev->guest_features;
}

static void virtio_iommu_save(QEMUFile *f, void *opaque)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(opaque);

    virtio_save(vdev, f);
}
    
static void virtio_iommu_save_device(VirtIODevice *vdev, QEMUFile *f)
{
    VirtIOIommu *s = VIRTIO_IOMMU(vdev);
    VirtIOIommuReq *req = s->rq;

    while (req) {
        qemu_put_sbyte(f, 1);
        qemu_put_buffer(f, (unsigned char *)&req->elem,
                        sizeof(VirtQueueElement));
        req = req->next;
    }
    qemu_put_sbyte(f, 0);
}

static int virtio_iommu_load(QEMUFile *f, void *opaque, int version_id)
{
    VirtIOIommu *s = opaque;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    if (version_id != 2)
        return -EINVAL;

    return virtio_load(vdev, f, version_id);
}

static int virtio_iommu_load_device(VirtIODevice *vdev, QEMUFile *f,
                                  int version_id)
{
    VirtIOIommu *s = VIRTIO_IOMMU(vdev);

    printf("=====virtio_iommu_load_device\n");
    while (qemu_get_sbyte(f)) {
        VirtIOIommuReq *req = virtio_iommu_alloc_request(s);
        qemu_get_buffer(f, (unsigned char *)&req->elem,
                        sizeof(VirtQueueElement));
        req->next = s->rq;
        s->rq = req;

        virtqueue_map_sg(req->elem.in_sg, req->elem.in_addr,
            req->elem.in_num, 1);
        virtqueue_map_sg(req->elem.out_sg, req->elem.out_addr,
            req->elem.out_num, 0);
    }

    return 0;
}

static void virtio_iommu_vmstate_change_cb(void *opaque, int running,  
                                      RunState state) 
{
    printf("virtio_iommu_vmstate_change_cb\n");
}

static void virtio_iommu_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOIommu *s = VIRTIO_IOMMU(dev);
//    VirtIOPCIProxy *proxy = VIRTIO_PCI(dev);
    VirtIOIommuConf *iommu = &(s->iommu);
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    static int virtio_iommu_id;
    int r;

    printf("virtio_iommu_device_realize, dev_state=%p\n", dev);
    virtio_init(vdev, "virtio-iommu", VIRTIO_ID_IOMMU, sizeof(struct virtio_iommu_config));

    s->rq = NULL;

    s->vq = virtio_add_queue(vdev, 128, virtio_iommu_handle_output);  // callback for front-end
    s->complete_request = virtio_iommu_complete_request;

    s->change = qemu_add_vm_change_state_handler(virtio_iommu_vmstate_change_cb, s);
    register_savevm(dev, "virtio-iommu", virtio_iommu_id++, 2,
                    virtio_iommu_save, virtio_iommu_load, s);

    iommu_vm_ppr_fd = open(IOMMU_VM_PPR_DEVICE, O_RDWR);
    if (iommu_vm_ppr_fd == -1) 
        printf("iommu_vm_ppr_fd open fail\n");
}

static void virtio_iommu_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOIommu *s = VIRTIO_IOMMU(dev);

    printf("virtio_iommu_device_unrealize\n");
    qemu_del_vm_change_state_handler(s->change);
    unregister_savevm(dev, "virtio-iommu", s);
    virtio_cleanup(vdev);
}

static void virtio_iommu_instance_init(Object *obj)
{
    VirtIOIommu *s = VIRTIO_IOMMU(obj);

    printf("virtio_iommu_instance_init\n");
    object_property_add_link(obj, "iothread", TYPE_IOTHREAD,
                             (Object **)&s->iommu.iothread,
                             qdev_prop_allow_set_link_before_realize,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE, NULL);
}

static Property virtio_iommu_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_iommu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    printf("virtio_iommu_class_init\n");
    dc->props = virtio_iommu_properties;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    vdc->realize = virtio_iommu_device_realize;
    vdc->unrealize = virtio_iommu_device_unrealize;
    vdc->get_config = virtio_iommu_update_config;
    vdc->set_config = virtio_iommu_set_config;
    vdc->get_features = virtio_iommu_get_features;
    vdc->set_status = virtio_iommu_set_status;
    vdc->reset = virtio_iommu_reset;
    vdc->save = virtio_iommu_save_device;
    vdc->load = virtio_iommu_load_device;
}

static const TypeInfo virtio_device_info = {
    .name = TYPE_VIRTIO_IOMMU,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOIommu),
    .instance_init = virtio_iommu_instance_init,
    .class_init = virtio_iommu_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_device_info);
}

type_init(virtio_register_types);
