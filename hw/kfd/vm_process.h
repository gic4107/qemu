#include <stdint.h>

#define VM_PROCESS_NUM 100

struct vm_process {
    uint64_t vm_task;
    uint64_t vm_mm;
    uint64_t vm_pgd_gpa;
    uint64_t *doorbell_region_hva;
//    uint64_t *event_trigger_addr;
};
