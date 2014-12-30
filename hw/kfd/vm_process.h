#include <stdint.h>

#define VM_PROCESS_NUM 100

struct vm_process {
    uint64_t match;
//    int      *qid;
    uint64_t *doorbell_region_hva;
//    uint64_t *event_trigger_addr;
};
