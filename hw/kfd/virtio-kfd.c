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
#include "hw/virtio/virtio-kfd.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-access.h"

#include <linux/kfd_ioctl.h>
#include <sys/mman.h>
#include "virtio_kfd_priv.h"
#include "shadow_process.h"

#define SHADOW_PROCESS_NUM 100
#define COMMAND_LEN 100

static struct shadow_process shadow_processes[SHADOW_PROCESS_NUM];
static int shadow_process_count;

VirtIOKfdReq *virtio_kfd_alloc_request(VirtIOKfd *s)
{
    VirtIOKfdReq *req = g_slice_new(VirtIOKfdReq);
    req->dev = s;
    req->qiov.size = 0;
    req->next = NULL;
    return req;
}

void virtio_kfd_free_request(VirtIOKfdReq *req)
{
    if (req) {
        g_slice_free(VirtIOKfdReq, req);
    }
}

static void virtio_kfd_complete_request(VirtIOKfdReq *req,
                                        unsigned char status)
{
    VirtIOKfd *s = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    printf("virtio_kfd_complete_request\n");
    trace_virtio_kfd_req_complete(req, status);

    stb_p(&req->in->status, status);
    virtqueue_push(s->vq, &req->elem, req->qiov.size + sizeof(*req->in));
    virtio_notify(vdev, s->vq);
}

static void virtio_kfd_req_complete(VirtIOKfdReq *req, unsigned char status)
{
    req->dev->complete_request(req, status);
}

static VirtIOKfdReq *virtio_kfd_get_request(VirtIOKfd *s)
{
    VirtIOKfdReq *req = virtio_kfd_alloc_request(s);

    if (!virtqueue_pop(s->vq, &req->elem)) {
        virtio_kfd_free_request(req);
        return NULL;
    }

    return req;
}

static struct shadow_process* get_shadow_process_pid(int pid)
{
    int i;
    for(i=0; i<=shadow_process_count; i++)
        if(shadow_processes[i].pid == pid)
            return &shadow_processes[i];
    return NULL;
}

static struct shadow_process* get_shadow_process_match(uint64_t match)
{
    int i;
    for(i=0; i<=shadow_process_count; i++)
        if(shadow_processes[i].match == match)
            return &shadow_processes[i];
    return NULL;
}

static void sig_handler(int signum, siginfo_t *info, void *ctx)
{
    struct shadow_process *shadow_process;
    if(signum == SHADOW_PROCESS_SIG) {        
        printf("parent got signal, %d\n", info->si_value.sival_int);
        shadow_process = get_shadow_process_pid(info->si_value.sival_int);
        if(shadow_process)
            shadow_process->signal = 1;
    }
}

static void kick_shadow_process(struct shadow_process *shadow_process, struct forward_data *data)
{
    memcpy(shadow_process->shmem, data, sizeof(*data));
    kill(shadow_process->pid, SHADOW_PROCESS_SIG);
}

static void wait_shadow_process(struct shadow_process *shadow_process)
{
    sigset_t zeroset;
    sigemptyset(&zeroset);
    shadow_process->signal = 0;
    while(shadow_process->signal == 0)
        sigsuspend(&zeroset);
}

static int virtkfd_open_shadow_process(struct iovec *param)
{
    uint64_t match;
    pid_t pid;
    int i;
    int ret;
    struct shadow_process *shadow_process = &shadow_processes[shadow_process_count];
    char shm_name[20] = "/shm_shadow_process";
    char parent_pid[10];
    struct forward_data data;

    // get match from front-end
    iov_to_buf(param, 1, 0, &match, sizeof(match));
    printf("match=0x%llx\n", match); 
    for(i=0; i<shadow_process_count; i++) {
        if(match == shadow_processes[i].match) {
            printf("match 0x%llx already exist\n", match);
            return -1;
        }
    }
    shadow_process->match = match; 

    // initialize shared memory 
    char tmp[2];
    sprintf(tmp, "%d", shadow_process_count);
    strcat(shm_name, tmp);
    shadow_process->shm_id = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    if(shadow_process->shm_id < 0) {
        fprintf(stderr, "%s open fail\n", shm_name);
        ret = -1;
        goto error_shm;
    }
    ftruncate(shadow_process->shm_id, SHMEM_SIZE);
    strcpy(shadow_process->shm_name, shm_name);

    shadow_process->shmem = mmap(NULL, SHMEM_SIZE, PROT_WRITE | PROT_READ, 
                                MAP_SHARED, shadow_process->shm_id, 0);
    if(shadow_process->shmem < 0) {
        fprintf(stderr, "shmem map fail\n");
        goto error_mmap; 
    }
    memset(shadow_process->shmem, 0, SHMEM_SIZE);

    // fork shadow process
    sprintf(parent_pid, "%d", getpid());
    pid = fork();
    if(pid < 0) {
        fprintf(stderr, "fork fail\n");
        ret = -1;
        goto error;
    }
    else if(pid == 0) {
        ret = execl(SHADOW_PROCESS_EXEC_PATH, "shadow_process", shm_name, parent_pid, NULL);
        if(ret < 0) {
            fprintf(stderr, "exec fail\n");
            goto error;
        }
    }
    shadow_process->pid = pid;
    while(1) {
        wait_shadow_process(shadow_process);
        memcpy(&data, shadow_process->shmem, sizeof(data));
        if(data.cmd == SHADOW_PROCESS_EXEC_SUCC)
            break;
    }

    shadow_process_count++;      // may need lock
    printf("virtkfd_open success\n");
    return 1;
error:
    munmap(shadow_process->shmem, SHMEM_SIZE);
error_mmap:
    shm_unlink(shm_name);
error_shm:
    shadow_process->match = 0;
    return ret;
}

static int virtkfd_close_shadow_process(struct iovec *param)
{
    uint64_t match;
    struct shadow_process *shadow_process;
    // get match from front-end

    iov_to_buf(param, 1, 0, &match, sizeof(match));
    printf("match=0x%llx\n", match); 
    shadow_process = get_shadow_process_match(match);
    if(shadow_process == NULL) {
        printf("close shadow_process not match 0x%llx\n", match);
        return -1;
    }
    munmap(shadow_process->shmem, SHMEM_SIZE);
    shm_unlink(shadow_process->shm_name); 
    shadow_process_count--;
}

static int virtkfd_get_sysinfo(struct iovec *param)
{
    struct virtkfd_sysfs_info sys_info;
    int i;
    FILE *fd;
    char output[1000];
    const char cat_sysfs[100] = "cat /sys/dev/char/250\:0/topology/";
    char path[100];

    memset(&sys_info, 0, sizeof(sys_info));
    // generation_id
    fd = popen("cat /sys/dev/char/250\:0/topology/generation_id", "r");
    if(!fd) {
        printf("fail to get generation_id\n");
        return -1;
    }
    fgets(output, 1000, fd);
    sys_info.system_properties.generation_count = atoi(output);
    pclose(fd);

    // system_properties
    fd = popen("cat /sys/dev/char/250\:0/topology/system_properties", "r");
    if(!fd) {
        printf("fail to get system_properties\n");
        return -1;
    }
    while(fgets(output, 1000, fd) != NULL) {
        if(strstr(output, "platform_oem")) {
            for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
            sys_info.system_properties.platform_oem = atoll(output+i); 
        }
        else if(strstr(output, "platform_id")) {
            for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
            sys_info.system_properties.platform_id = atoll(output+i); 
        }
        else if(strstr(output, "platform_rev")) {
            for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
            sys_info.system_properties.platform_rev = atoll(output+i); 
        }
        else {
            printf("Known system_properties\n");
            return -1;
        }
    }
    pclose(fd);

    // node count
    fd = popen("ls /sys/dev/char/250\:0/topology/nodes/", "r");
    if(!fd) {
        printf("fail to get node number\n");
        return -1;
    }
    fgets(output, 1000, fd);
    for(i=0; i<PROPERTIES_NODE_MAX; i++) {
        char str_i[2];
        sprintf(str_i, "%d", i);
        if(!strstr(output, str_i))
            break;
    }
    sys_info.node_count = i;
        
    // for each node
    int node;
    for(node=0; node<sys_info.node_count; node++) {
        // gpu_id
        fd = popen("cat /sys/dev/char/250\:0/topology/nodes/0/gpu_id", "r");
        fgets(output, 1000, fd);
        sys_info.topology_device[node].gpu_id = atoi(output);
        pclose(fd);

        // name
        fd = popen("cat /sys/dev/char/250\:0/topology/nodes/0/name", "r");
        fgets(output, 1000, fd);
        strcpy(sys_info.topology_device[node].name, output);
        pclose(fd);
        
        // properties
        fd = popen("cat /sys/dev/char/250\:0/topology/nodes/0/properties", "r");
        while(fgets(output, 1000, fd) != NULL) {
            if(strstr(output, "cpu_cores_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.cpu_cores_count = atoi(output+i); 
            }
            else if(strstr(output, "simd_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.simd_count = atoi(output+i); 
            }
            else if(strstr(output, "mem_banks_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.mem_banks_count = atoi(output+i); 
            }
            else if(strstr(output, "caches_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.caches_count = atoi(output+i); 
            }
            else if(strstr(output, "io_links_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.io_links_count = atoi(output+i); 
            }
            else if(strstr(output, "cpu_core_id_base")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.cpu_core_id_base = atoi(output+i); 
            }
            else if(strstr(output, "simd_id_base")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.simd_id_base = atoi(output+i); 
            }
            else if(strstr(output, "capability")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.capability = atoi(output+i); 
            }
            else if(strstr(output, "max_waves_per_simd")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.max_waves_per_simd = atoi(output+i); 
            }
            else if(strstr(output, "lds_size_in_kb")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.lds_size_in_kb = atoi(output+i); 
            }
            else if(strstr(output, "gds_size_in_kb")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.gds_size_in_kb = atoi(output+i); 
            }
            else if(strstr(output, "wave_front_size")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.wave_front_size = atoi(output+i); 
            }
            else if(strstr(output, "array_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.array_count = atoi(output+i); 
            }
            else if(strstr(output, "simd_arrays_per_engine")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.simd_arrays_per_engine = atoi(output+i); 
            }
            else if(strstr(output, "cu_per_simd_array")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.cu_per_simd_array = atoi(output+i); 
            }
            else if(strstr(output, "simd_per_cu")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.simd_per_cu = atoi(output+i); 
            }
            else if(strstr(output, "max_slots_scratch_cu")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.max_slots_scratch_cu = atoi(output+i); 
            }
            else if(strstr(output, "engine_id")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.engine_id = atoi(output+i); 
            }
            else if(strstr(output, "vendor_id")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.vendor_id = atoi(output+i); 
            }
            else if(strstr(output, "device_id")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.device_id = atoi(output+i); 
            }
            else if(strstr(output, "location_id")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.location_id = atoi(output+i); 
            }
            else if(strstr(output, "max_engine_clk_fcompute")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.max_engine_clk_fcompute = atoi(output+i); 
            }
            else if(strstr(output, "local_mem_size")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.local_mem_size = atoll(output+i); 
            }
            else if(strstr(output, "max_engine_clk_ccompute")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.max_engine_clk_ccompute = atoi(output+i); 
            }
/*            else if(strstr(output, "marketing_name")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                sys_info.topology_device[node].node_properties.marketing_name = atoi(output+i); 
            }*/
            else {
                printf("Known node properties %s\n", output);
            }
        }
        pclose(fd);
        
        // cache count
        fd = popen("ls /sys/dev/char/250\:0/topology/nodes/0/caches", "r");
        if(!fd) {
            printf("fail to get cache count\n");
            return -1;
        }
        while(fgets(output, 1000, fd) != NULL) {
            sys_info.topology_device[node].cache_count++;
        }
        pclose(fd);
        
        // for each cache
        int cache;
        const char cache_cmd[COMMAND_LEN] = "cat /sys/dev/char/250\:0/topology/nodes/0/caches/";
        for(cache=0; cache<sys_info.topology_device[node].cache_count; cache++) {
            char cmd[COMMAND_LEN];
            char str_cache[2];
            sprintf(str_cache, "%d", cache);
            strcpy(cmd, cache_cmd);
            strcat(cmd, str_cache);
            // get cache properties
            strcat(cmd, "/properties");    
            fd = popen(cmd, "r");
            while(fgets(output, 1000, fd) != NULL) {
                if(strstr(output, "processor_id_low")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].cache_properties[cache].processor_id_low = atoi(output+i); 
                }
                else if(strstr(output, "level")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].cache_properties[cache].cache_level = atoi(output+i); 
                }
                else if(strstr(output, "cache_line_size")) {        // must before "size", because the strstr!
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].cache_properties[cache].cacheline_size = atoi(output+i); 
                }
                else if(strstr(output, "size")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].cache_properties[cache].cache_size = atoi(output+i); 
                }
                else if(strstr(output, "cache_lines_per_tag")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].cache_properties[cache].cachelines_per_tag = atoi(output+i); 
                }
                else if(strstr(output, "association")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].cache_properties[cache].cache_assoc = atoi(output+i); 
                }
                else if(strstr(output, "latency")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].cache_properties[cache].cache_latency = atoi(output+i); 
                }
                else if(strstr(output, "type")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].cache_properties[cache].cache_type = atoi(output+i); 
                }
                else if(strstr(output, "sibling_map")) {
                    char *num_base;
                    int index = 0;
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    num_base = output+i;
                    for(index=0; index<KFD_TOPOLOGY_CPU_SIBLINGS; index++) {
                        sys_info.topology_device[node].cache_properties[cache].sibling_map[index] = atoi(num_base);
                        for(; *num_base!=',' && *num_base!='\0'; num_base++);
                        num_base++;
                    }
                }
                else {
                    printf("Known cache properties\n");
                }
            }
            pclose(fd);
        }

        // iolink count
        fd = popen("ls /sys/dev/char/250\:0/topology/nodes/0/io_links", "r");
        if(!fd) {
            printf("fail to get iolink count\n");
            return -1;
        }
        while(fgets(output, 1000, fd) != NULL) {
            sys_info.topology_device[node].io_link_count++;
        }
        pclose(fd);

        // for each iolink
        int iolink;
        const char iolink_cmd[COMMAND_LEN] = "cat /sys/dev/char/250\:0/topology/nodes/0/io_links/";
        for(iolink=0; iolink<sys_info.topology_device[node].io_link_count; iolink++) {
            char cmd[COMMAND_LEN];
            char str_iolink[2];
            sprintf(str_iolink, "%d", iolink);
            strcpy(cmd, iolink_cmd);
            strcat(cmd, str_iolink);
            // get iolink properties ... No attribute now.
        }

        // membank count
        fd = popen("ls /sys/dev/char/250\:0/topology/nodes/0/mem_banks", "r");
        if(!fd) {
            printf("fail to get membank count\n");
            return -1;
        }
        while(fgets(output, 1000, fd) != NULL) {
            sys_info.topology_device[node].mem_bank_count++;
        }
        pclose(fd);

        // for each membank
        int membank;
        const char membank_cmd[COMMAND_LEN] = "cat /sys/dev/char/250\:0/topology/nodes/0/mem_banks/";
        for(membank=0; membank<sys_info.topology_device[node].mem_bank_count; membank++) {
            char cmd[COMMAND_LEN];
            char str_membank[2];
            sprintf(str_membank, "%d", membank);
            strcpy(cmd, membank_cmd);
            strcat(cmd, str_membank);
            // get membank properties
            strcat(cmd, "/properties");    
            fd = popen(cmd, "r");
            while(fgets(output, 1000, fd) != NULL) {
                if(strstr(output, "heap_type")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].mem_properties[membank].heap_type = atoi(output+i); 
                }
                else if(strstr(output, "size_in_bytes")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].mem_properties[membank].size_in_bytes = atoll(output+i); 
                }
                else if(strstr(output, "flags")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].mem_properties[membank].flags = atoi(output+i); 
                }
                else if(strstr(output, "width")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].mem_properties[membank].width = atoi(output+i); 
                }
                else if(strstr(output, "mem_clk_max")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    sys_info.topology_device[node].mem_properties[membank].mem_clk_max = atoi(output+i); 
                }
                else {
                    printf("Known membank properties\n");
                }
            }
            pclose(fd);
        }
    }   // end for node loop

    iov_from_buf(param, 1, 0, &sys_info, sizeof(sys_info));

    return 1;
}
/*
static int virtkfd_get_process_apertures(struct iovec *iov_param, int match)
{
    int i;
    struct forwarder *forwarder;
    struct forward_data *data;
    struct kfd_ioctl_get_process_apertures_args *args;
    printf("virtkfd_get_process_apertures === match=0x%x\n", match);

    forwarder = get_forwarder_match(match);
    if(forwarder == NULL) {
        fprintf(stderr, "get forwarder from match %d fail\n", match);
        return -1;
    } 

    data = (struct forward_data*)forwarder->shmem;
    // get param from front-end to forward_data
    data->cmd = SHADOW_PROCESS_GET_PROCESS_APERTURES;
    data->param_size = sizeof(struct kfd_ioctl_get_process_apertures_args);
    iov_to_buf(iov_param, 1, 0, &(data->param), data->param_size);
    
    kick_forwarder(forwarder, data);
    wait_forwarder(forwarder);
    
    args = &data->param;
    iov_from_buf(iov_param, 1, 0, &(data->param), data->param_size);
    printf("virtkfd_get_process_apertures done\n");
    return 1;
}

static int virtkfd_get_clock_counters(struct iovec *iov_param, int match)
{
    int i;
    struct forwarder *forwarder;
    struct forward_data *data;
    struct kfd_ioctl_get_clock_counters_args *args;
    printf("virtkfd_get_clock_counters=== match=0x%x\n", match);

    forwarder = get_forwarder_match(match);
    if(forwarder == NULL) {
        fprintf(stderr, "get forwarder from match %d fail\n", match);
        return -1;
    } 

    data = (struct forward_data*)forwarder->shmem;
    // get param from front-end to forward_data
    data->cmd = SHADOW_PROCESS_GET_CLOCK_COUNTERS;
    data->param_size = sizeof(struct kfd_ioctl_get_clock_counters_args);
    iov_to_buf(iov_param, 1, 0, &(data->param), data->param_size);
    
    kick_forwarder(forwarder, data);
    wait_forwarder(forwarder);
    
    args = &data->param;
    iov_from_buf(iov_param, 1, 0, &(data->param), data->param_size);
    printf("virtkfd_get_clock_counters done\n");
    return 1;
}

static int virtkfd_set_memory_policy(struct iovec *iov_param, int match)
{
    int i;
    struct forwarder *forwarder;
    struct forward_data *data;
    struct kfd_ioctl_get_clock_counters_args *args;
    printf("virtkfd_set_memory_policy=== match=0x%x\n", match);

    forwarder = get_forwarder_match(match);
    if(forwarder == NULL) {
        fprintf(stderr, "get forwarder from match %d fail\n", match);
        return -1;
    } 

    data = (struct forward_data*)forwarder->shmem;
    // get param from front-end to forward_data
    data->cmd = SHADOW_PROCESS_SET_MEMORY_POLICY;
    data->param_size = sizeof(struct kfd_ioctl_set_memory_policy_args);
    iov_to_buf(iov_param, 1, 0, &(data->param), data->param_size);
    
    kick_forwarder(forwarder, data);
    wait_forwarder(forwarder);
    
    args = &data->param;
    iov_from_buf(iov_param, 1, 0, &(data->param), data->param_size);
    printf("virtkfd_set_memory_policy done\n");
    return 1;
}
*/

/*
    Modify args.gpu_id to 40810 if userland not send 40810
*/
static void check_gpu_id(void *args, int cmd)
{
    const int GPU_ID = 40810;
    switch(cmd) {
    case SHADOW_PROCESS_CREATE_QUEUE:
        if(((struct kfd_ioctl_create_queue_args*)args)->gpu_id != GPU_ID)
            ((struct kfd_ioctl_create_queue_args*)args)->gpu_id = GPU_ID;
        break;
    case SHADOW_PROCESS_GET_CLOCK_COUNTERS:
        if(((struct kfd_ioctl_get_clock_counters_args*)args)->gpu_id != GPU_ID)
            ((struct kfd_ioctl_get_clock_counters_args*)args)->gpu_id = GPU_ID;
        break;
    case SHADOW_PROCESS_SET_MEMORY_POLICY:
        if(((struct kfd_ioctl_set_memory_policy_args*)args)->gpu_id != GPU_ID)
            ((struct kfd_ioctl_set_memory_policy_args*)args)->gpu_id = GPU_ID;
        break;
    default:
        break;
    }
}
static int virtkfd_send_shadow_process_command(struct iovec *iov_param, 
                                            int param_size, int cmd, uint64_t match)
{
    struct shadow_process *shadow_process;
    struct forward_data *data;
    void *args;
    printf("virtkfd_send_shadow_process_command === match=0x%llx cmd=%d\n", match, cmd);

    shadow_process = get_shadow_process_match(match);
    if(shadow_process == NULL) {
        fprintf(stderr, "get shadow_process from match 0x%llx fail\n", match);
        return -1;
    } 

    data = (struct forward_data*)shadow_process->shmem;
    // get param from front-end to forward_data
    data->cmd = cmd;
    data->param_size = param_size;
    if(param_size+4 > SHMEM_MMAP_DOORBELL_START)
        printf("!!!!! param in shmem touch mmap region !!!!!\n");
    iov_to_buf(iov_param, 1, 0, &(data->param), param_size);

    check_gpu_id(&data->param, cmd);
    
    kick_shadow_process(shadow_process, data);
    wait_shadow_process(shadow_process);
    
    args = &data->param;    // use for gdb check value

    if(cmd == SHADOW_PROCESS_CREATE_EVENT) {        // event_trigger_address from KFD

    }
    else if(cmd == SHADOW_PROCESS_CREATE_QUEUE) {   // doorbell_offset from KFD
        // remap doorbell polling address to guest
//        int qid = ((struct kfd_ioctl_create_queue_args*)args)->queue_id;
//        uint64_t poll_hva = data + SHMEM_MMAP_DOORBELL_START + qid * DOORBELL_SIZE;
//        uint64_t poll_gpa =        ;
        // get GPA of doorbell polling address 
    }
//    else {
        iov_from_buf(iov_param, 1, 0, &(data->param), param_size);
//    }
    printf("send shadow_process cmd %d done\n", cmd);
    return 1;
}

void virtio_kfd_handle_request(VirtIOKfdReq *req)
{
    uint32_t type;
    struct iovec *in_iov = req->elem.in_sg;
    struct iovec *iov = req->elem.out_sg;
    unsigned in_num = req->elem.in_num;
    unsigned out_num = req->elem.out_num;
    int status = VIRTIO_KFD_S_OK; 
    int ret;

//    printf("virtio_kfd_handle_request ... in_num=%d out_num=%d\n", in_num, out_num);
//    printf("out_iov[0]: base=%p, len=%d\n", iov[0].iov_base, iov[0].iov_len);
//    printf("in_iov[0]: base=%p, len=%d\n", in_iov[0].iov_base, in_iov[0].iov_len);
//    printf("in_iov[1]: base=%p, len=%d\n", in_iov[1].iov_base, in_iov[1].iov_len);

    if (req->elem.out_num < 1 || req->elem.in_num < 1) {
        error_report("virtio-kfd missing headers");
        exit(1);
    }

/*    if (unlikely(iov_to_buf(iov, out_num, 0, &req->out,         // copy vring data into req->out
                            sizeof(req->out)) != sizeof(req->out))) {
        error_report("virtio-kfd request outhdr too short");
        exit(1);
    }
*/
    iov_to_buf(&iov[0], 1, 0, &req->out.cmd, sizeof(int));
    iov_to_buf(&iov[1], 1, 0, &req->out.match, sizeof(uint64_t));
    printf("command=%d, match=0x%llx\n", req->out.cmd, req->out.match); 
     

//    iov_discard_front(&iov, &out_num, sizeof(req->out));

    if (in_num < 1 ||
        in_iov[in_num - 1].iov_len < sizeof(struct virtio_kfd_inhdr)) {
        error_report("virtio-kfd request inhdr too short");
        exit(1);
    }

    req->param = in_iov[0];                         // param
    req->in = (void *)in_iov[in_num - 1].iov_base   // status
              + in_iov[in_num - 1].iov_len
              - sizeof(struct virtio_kfd_inhdr);
//    iov_discard_back(in_iov, &in_num, sizeof(struct virtio_kfd_inhdr));

    switch(req->out.cmd) {
    case VIRTKFD_OPEN:
        printf("VIRTKFD_OPEN\n");
        ret = virtkfd_open_shadow_process(&req->param);
        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;        
    case VIRTKFD_CLOSE:
        printf("VIRTKFD_CLOSE\n");
        ret = virtkfd_close_shadow_process(&req->param);
        break;
    case VIRTKFD_GET_SYSINFO:
        printf("VIRTKFD_GET_SYSINFO\n");
        ret = virtkfd_get_sysinfo(&req->param);
        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_GET_VERSION:
        printf("VIRTKFD_\n");
        break;
    case VIRTKFD_CREATE_QUEUE:
        printf("VIRTKFD_CREATE_QUEUE\n");
        ret = virtkfd_send_shadow_process_command(&req->param, 
                    sizeof(struct kfd_ioctl_create_queue_args), 
                    SHADOW_PROCESS_CREATE_QUEUE, req->out.match); 
        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_DESTROY_QUEUE:
        printf("VIRTKFD_DESTROY_QUEUE\n");

        break;
    case VIRTKFD_SET_MEMORY_POLICY:
        printf("VIRTKFD_SET_MEMORY_POLICY\n");
        ret = virtkfd_send_shadow_process_command(&req->param, 
                    sizeof(struct kfd_ioctl_set_memory_policy_args), 
                    SHADOW_PROCESS_SET_MEMORY_POLICY, req->out.match); 
        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_GET_CLOCK_COUNTERS:
        printf("VIRTKFD_GET_CLOCK_COUNTERS\n");
        ret = virtkfd_send_shadow_process_command(&req->param, 
                    sizeof(struct kfd_ioctl_get_clock_counters_args), 
                    SHADOW_PROCESS_GET_CLOCK_COUNTERS, req->out.match); 
        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_GET_PROCESS_APERTURES:
        printf("VIRTKFD_GET_PROCESS_APERTURES \n");
        ret = virtkfd_send_shadow_process_command(&req->param, 
                    sizeof(struct kfd_ioctl_get_process_apertures_args), 
                    SHADOW_PROCESS_GET_PROCESS_APERTURES, req->out.match); 
        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_UPDATE_QUEUE:
        printf("VIRTKFD_UPDATE_QUEUE\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_DBG_REGISTER:
        printf("VIRTKFD_DBG_REGISTER\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_DBG_UNREGISTER:
        printf("VIRTKFD_DBG_UNREGISTER\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_DBG_ADDRESS_WATCH:
        printf("VIRTKFD_DBG_ADDRESS_WATCH\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_DBG_WAVE_CONTROL:
        printf("VIRTKFD_DBG_WAVE_CONTROL\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_PMC_ACQUIRE_ACCESS:
        printf("VIRTKFD_PMC_ACQUIRE_ACCESS\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_PMC_RELEASE_ACCESS:
        printf("VIRTKFD_PMC_RELEASE_ACCESS\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_CREATE_VIDMEM:
        printf("VIRTKFD_CREATE_VIDMEM\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_DESTROY_VIDMEM:
        printf("VIRTKFD_DESTROY_VIDMEM\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_CREATE_EVENT:
        printf("VIRTKFD_CREATE_EVENT\n");
        ret = virtkfd_send_shadow_process_command(&req->param, 
                    sizeof(struct kfd_ioctl_create_event_args), 
                    SHADOW_PROCESS_CREATE_EVENT, req->out.match); 
        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_DESTROY_EVENT:
        printf("VIRTKFD_DESTROY_EVENT\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_SET_EVENT:
        printf("VIRTKFD_SET_EVENT\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_RESET_EVENT:
        printf("VIRTKFD_RESET_EVENT\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_WAIT_EVENTS:
        printf("VIRTKFD_WAIT_EVENTS\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    case VIRTKFD_OPEN_GRAPHIC_HANDLE:
        printf("VIRTKFD_OPEN_GRAPHIC_HANDLE\n");

        if(ret == -1)
            status = VIRTIO_KFD_S_IOERR;
        break;
    default:
        printf("Known command\n");
        status = VIRTIO_KFD_S_UNSUPP;
    }

    virtio_kfd_req_complete(req, status);
    virtio_kfd_free_request(req);
}

static void virtio_kfd_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOKfd *s = VIRTIO_KFD(vdev);
    VirtIOKfdReq *req;

//    printf("virtio_kfd_handle_output\n");

    while ((req = virtio_kfd_get_request(s))) { // get one request (separator: next flag)
        virtio_kfd_handle_request(req);
    }

    /*
     * FIXME: Want to check for completions before returning to guest mode,
     * so cached reads and writes are reported as quickly as possible. But
     * that should be done in the generic block layer.
     */
}

static void virtio_kfd_reset(VirtIODevice *vdev)
{
    VirtIOKfd *s = VIRTIO_KFD(vdev);

    printf("virtio_kfd_reset\n");
    /*
     * This should cancel pending requests, but can't do nicely until there
     * are per-device request lists.
     */
//    bdrv_drain_all();
//    bdrv_set_enable_write_cache(s->cs, s->original_wce);
}

/* coalesce internal state, copy to pci i/o region 0
 */
static void virtio_kfd_update_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOKfd *s = VIRTIO_KFD(vdev);
    struct virtio_kfd_config kfdcfg;
    uint64_t capacity;
//    int kfd_size = s->conf->logical_block_size;

    printf("virtio_kfd_update_config\n");
/*
    bdrv_get_geometry(s->cs, &capacity);
    memset(&kfdcfg, 0, sizeof(kfdcfg));
    virtio_stq_p(vdev, &kfdcfg.capacity, capacity);
    virtio_stl_p(vdev, &kfdcfg.seg_max, 128 - 2);
    virtio_stw_p(vdev, &kfdcfg.cylinders, s->conf->cyls);
    virtio_stl_p(vdev, &kfdcfg.kfd_size, kfd_size);
    virtio_stw_p(vdev, &kfdcfg.min_io_size, s->conf->min_io_size / kfd_size);
    virtio_stw_p(vdev, &kfdcfg.opt_io_size, s->conf->opt_io_size / kfd_size);
    kfdcfg.heads = s->conf->heads;
*/
    /*
     * We must ensure that the block device capacity is a multiple of
     * the logical block size. If that is not the case, let's use
     * sector_mask to adopt the geometry to have a correct picture.
     * For those devices where the capacity is ok for the given geometry
     * we don't touch the sector value of the geometry, since some devices
     * (like s390 dasd) need a specific value. Here the capacity is already
     * cyls*heads*secs*kfd_size and the sector value is not block size
     * divided by 512 - instead it is the amount of kfd_size blocks
     * per track (cylinder).
     */
/*
    if (bdrv_getlength(s->cs) /  s->conf->heads / s->conf->secs % kfd_size) {
        kfdcfg.sectors = s->conf->secs & ~s->sector_mask;
    } else {
        kfdcfg.sectors = s->conf->secs;
    }
    kfdcfg.size_max = 0;
    kfdcfg.physical_block_exp = get_physical_block_exp(s->conf);
    kfdcfg.alignment_offset = 0;
    kfdcfg.wce = bdrv_enable_write_cache(s->cs);
    memcpy(config, &kfdcfg, sizeof(struct virtio_kfd_config));
*/
}

static void virtio_kfd_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VirtIOKfd *s = VIRTIO_KFD(vdev);
    struct virtio_kfd_config kfdcfg;

    printf("virtio_kfd_set_config\n");
/*
    memcpy(&kfdcfg, config, sizeof(kfdcfg));

    aio_context_acquire(bdrv_get_aio_context(s->cs));
    bdrv_set_enable_write_cache(s->cs, kfdcfg.wce != 0);
    aio_context_release(bdrv_get_aio_context(s->cs));
*/
}

static uint32_t virtio_kfd_get_features(VirtIODevice *vdev, uint32_t features)
{
    VirtIOKfd *s = VIRTIO_KFD(vdev);

    printf("virtio_kfd_get_features\n");
/*
    features |= (1 << VIRTIO_KFD_F_SEG_MAX);
    features |= (1 << VIRTIO_KFD_F_GEOMETRY);
    features |= (1 << VIRTIO_KFD_F_TOPOLOGY);
    features |= (1 << VIRTIO_KFD_F_BLK_SIZE);
    features |= (1 << VIRTIO_KFD_F_SCSI);

    if (s->kfd.config_wce) {
        features |= (1 << VIRTIO_KFD_F_CONFIG_WCE);
    }
    if (bdrv_enable_write_cache(s->cs))
        features |= (1 << VIRTIO_KFD_F_WCE);

    if (bdrv_is_read_only(s->cs))
        features |= 1 << VIRTIO_KFD_F_RO;
*/
    return features;
}

static void virtio_kfd_set_status(VirtIODevice *vdev, uint8_t status)
{
    VirtIOKfd *s = VIRTIO_KFD(vdev);
    uint32_t features;

    printf("virtio_kfd_set_status\n");
    if (!(status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        return;
    }

    features = vdev->guest_features;

    /* A guest that supports VIRTIO_KFD_F_CONFIG_WCE must be able to send
     * cache flushes.  Thus, the "auto writethrough" behavior is never
     * necessary for guests that support the VIRTIO_KFD_F_CONFIG_WCE feature.
     * Leaving it enabled would break the following sequence:
     *
     *     Guest started with "-drive cache=writethrough"
     *     Guest sets status to 0
     *     Guest sets DRIVER bit in status field
     *     Guest reads host features (WCE=0, CONFIG_WCE=1)
     *     Guest writes guest features (WCE=0, CONFIG_WCE=1)
     *     Guest writes 1 to the WCE configuration field (writeback mode)
     *     Guest sets DRIVER_OK bit in status field
     *
     * s->cs would erroneously be placed in writethrough mode.
     */
/*
    if (!(features & (1 << VIRTIO_KFD_F_CONFIG_WCE))) {
        aio_context_acquire(bdrv_get_aio_context(s->cs));
        bdrv_set_enable_write_cache(s->cs,
                                    !!(features & (1 << VIRTIO_KFD_F_WCE)));
        aio_context_release(bdrv_get_aio_context(s->cs));
    }
*/
}

static void virtio_kfd_save(QEMUFile *f, void *opaque)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(opaque);

    virtio_save(vdev, f);
}
    
static void virtio_kfd_save_device(VirtIODevice *vdev, QEMUFile *f)
{
    VirtIOKfd *s = VIRTIO_KFD(vdev);
    VirtIOKfdReq *req = s->rq;

    while (req) {
        qemu_put_sbyte(f, 1);
        qemu_put_buffer(f, (unsigned char *)&req->elem,
                        sizeof(VirtQueueElement));
        req = req->next;
    }
    qemu_put_sbyte(f, 0);
}

static int virtio_kfd_load(QEMUFile *f, void *opaque, int version_id)
{
    VirtIOKfd *s = opaque;
    VirtIODevice *vdev = VIRTIO_DEVICE(s);

    if (version_id != 2)
        return -EINVAL;

    return virtio_load(vdev, f, version_id);
}

static int virtio_kfd_load_device(VirtIODevice *vdev, QEMUFile *f,
                                  int version_id)
{
    VirtIOKfd *s = VIRTIO_KFD(vdev);

    while (qemu_get_sbyte(f)) {
        VirtIOKfdReq *req = virtio_kfd_alloc_request(s);
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

static void virtio_kfd_vmstate_change_cb(void *opaque, int running,  
                                      RunState state) 
{
    printf("virtio_kfd_vmstate_change_cb\n");
}

static void virtio_kfd_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOKfd *s = VIRTIO_KFD(dev);
    VirtIOKfdConf *kfd = &(s->kfd);
    static int virtio_kfd_id;
    struct sigaction sig_act;

    printf("virtio_kfd_device_realize\n");
    virtio_init(vdev, "virtio-kfd", VIRTIO_ID_KFD,
                sizeof(struct virtio_kfd_config));

    // register signal handler for communicating with shadow process
    sig_act.sa_sigaction = sig_handler;
    sig_act.sa_flags = SA_SIGINFO;
    if(sigaction(SHADOW_PROCESS_SIG, &sig_act, NULL) == SIG_ERR) {       // SHADOW_PROCESS_SIG cannot be caught, someone use it?
        printf("signal register fail\n");
    }

//    s->cs = kfd->conf.cs;
//    s->conf = &kfd->conf;
    s->rq = NULL;

    s->vq = virtio_add_queue(vdev, 128, virtio_kfd_handle_output);  // callback for front-end
    s->complete_request = virtio_kfd_complete_request;

    s->change = qemu_add_vm_change_state_handler(virtio_kfd_vmstate_change_cb, s);
    register_savevm(dev, "virtio-kfd", virtio_kfd_id++, 2,
                    virtio_kfd_save, virtio_kfd_load, s);
}

static void virtio_kfd_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOKfd *s = VIRTIO_KFD(dev);

    printf("virtio_kfd_device_unrealize\n");
    qemu_del_vm_change_state_handler(s->change);
    unregister_savevm(dev, "virtio-kfd", s);
    virtio_cleanup(vdev);
}

static void virtio_kfd_instance_init(Object *obj)
{
    VirtIOKfd *s = VIRTIO_KFD(obj);

    printf("virtio_kfd_instance_init\n");
    object_property_add_link(obj, "iothread", TYPE_IOTHREAD,
                             (Object **)&s->kfd.iothread,
                             qdev_prop_allow_set_link_before_realize,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE, NULL);
}

static Property virtio_kfd_properties[] = {
//    DEFINE_BLOCK_PROPERTIES(VirtIOKfd, kfd.conf),
//    DEFINE_BLOCK_CHS_PROPERTIES(VirtIOKfd, kfd.conf),
//    DEFINE_PROP_STRING("serial", VirtIOKfd, kfd.serial),
//    DEFINE_PROP_BIT("config-wce", VirtIOKfd, kfd.config_wce, 0, true),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_kfd_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    printf("virtio_kfd_class_init\n");
    dc->props = virtio_kfd_properties;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    vdc->realize = virtio_kfd_device_realize;
    vdc->unrealize = virtio_kfd_device_unrealize;
    vdc->get_config = virtio_kfd_update_config;
    vdc->set_config = virtio_kfd_set_config;
    vdc->get_features = virtio_kfd_get_features;
    vdc->set_status = virtio_kfd_set_status;
    vdc->reset = virtio_kfd_reset;
    vdc->save = virtio_kfd_save_device;
    vdc->load = virtio_kfd_load_device;
}

static const TypeInfo virtio_device_info = {
    .name = TYPE_VIRTIO_KFD,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOKfd),
    .instance_init = virtio_kfd_instance_init,
    .class_init = virtio_kfd_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_device_info);
}

type_init(virtio_register_types);
