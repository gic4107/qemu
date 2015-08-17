#ifndef IOMMU_VM_PPR_IOCTL_H
#define IOMMU_VM_PPR_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define IOMMU_VM_PPR_IOC 0xD8 

struct vm_mmu_notification {
    uint64_t mm;
    uint64_t start;
    uint64_t end;
};

// IVP stands for IOMMU_VM_PPR
#define IVP_IOC_SET_KVM_EVENTFD             _IOW(IOMMU_VM_PPR_IOC, 1, int)
#define IVP_IOC_VM_FINISH_PPR               _IOW(IOMMU_VM_PPR_IOC, 2, int)
#define IVP_IOC_MMU_CLEAR_FLUSH_YOUNG       _IOW(IOMMU_VM_PPR_IOC, 3, struct vm_mmu_notification)
#define IVP_IOC_MMU_CHANGE_PTE              _IOW(IOMMU_VM_PPR_IOC, 4, struct vm_mmu_notification)
#define IVP_IOC_MMU_INVALIDATE_PAGE         _IOW(IOMMU_VM_PPR_IOC, 5, struct vm_mmu_notification)
#define IVP_IOC_MMU_INVALIDATE_RANGE_START  _IOW(IOMMU_VM_PPR_IOC, 6, struct vm_mmu_notification)

#endif
