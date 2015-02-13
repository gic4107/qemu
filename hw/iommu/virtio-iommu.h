#ifndef VIRTIO_IOMMU_H
#define VIRTIO_IOMMU_H

#include <linux/kvm.h>

#define GPA_TO_HVA_MASK 0xffffffff
#define VIRTIO_IOMMU_MMAP_PPR_REGION           1
#define VIRTIO_IOMMU_VM_FINISH_PPR             2
#define VIRTIO_IOMMU_CLEAR_FLUSH_YOUNG         3
#define VIRTIO_IOMMU_CHANGE_PTE                4
#define VIRTIO_IOMMU_INVALIDATE_PAGE           5
#define VIRTIO_IOMMU_INVALIDATE_RANGE_START    6

#define VM_PPR_REGION_SIZE 4096

struct iommu_back_end {
    struct kvm_irqfd irqfd;
    size_t vm_ppr_region_hva;
};

#endif
