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
//#include "hw/block/block.h"
//#include "sysemu/blockdev.h"
#include "hw/virtio/virtio-kfd.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-access.h"
#include "kfd_cmd.h"

#include "virtio_kfd_priv.h"

#define COMMAND_LEN 100

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
    printf("get generation_id: %s %d\n", output, atoi(output));
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
            printf("platform_oem=%lld\n", atoll(output+i));
            sys_info.system_properties.platform_oem = atoll(output+i); 
        }
        else if(strstr(output, "platform_id")) {
            for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
            printf("platform_id=%lld\n", atoll(output+i));
            sys_info.system_properties.platform_id = atoll(output+i); 
        }
        else if(strstr(output, "platform_rev")) {
            for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
            printf("platform_rev=%lld\n", atoll(output+i));
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
    printf("get node: %s\n", output);
    for(i=0; i<PROPERTIES_NODE_MAX; i++) {
        char str_i[2];
        sprintf(str_i, "%d", i);
        if(!strstr(output, str_i))
            break;
    }
    sys_info.node_count = i;
    printf("node count=%d\n", sys_info.node_count);
        
    // for each node
    int node;
    for(node=0; node<sys_info.node_count; node++) {
        // gpu_id
        fd = popen("cat /sys/dev/char/250\:0/topology/nodes/0/gpu_id", "r");
        fgets(output, 1000, fd);
        printf("gpu_id=%d\n", atoi(output));
        sys_info.topology_device[node].gpu_id = atoi(output);
        pclose(fd);

        // name
        fd = popen("cat /sys/dev/char/250\:0/topology/nodes/0/name", "r");
        fgets(output, 1000, fd);
        printf("name=%s\n", output);
        strcpy(sys_info.topology_device[node].name, output);
        pclose(fd);
        
        // properties
        fd = popen("cat /sys/dev/char/250\:0/topology/nodes/0/properties", "r");
        while(fgets(output, 1000, fd) != NULL) {
            if(strstr(output, "cpu_cores_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("cpu_cores_count=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.cpu_cores_count = atoi(output+i); 
            }
            else if(strstr(output, "simd_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("simd_count=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.simd_count = atoi(output+i); 
            }
            else if(strstr(output, "mem_banks_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("mem_banks_count=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.mem_banks_count = atoi(output+i); 
            }
            else if(strstr(output, "caches_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("caches_count=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.caches_count = atoi(output+i); 
            }
            else if(strstr(output, "io_links_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("io_links_count=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.io_links_count = atoi(output+i); 
            }
            else if(strstr(output, "cpu_core_id_base")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("cpu_core_id_base=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.cpu_core_id_base = atoi(output+i); 
            }
            else if(strstr(output, "simd_id_base")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("simd_id_base=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.simd_id_base = atoi(output+i); 
            }
            else if(strstr(output, "capability")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("capability=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.capability = atoi(output+i); 
            }
            else if(strstr(output, "max_waves_per_simd")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("max_waves_per_simd=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.max_waves_per_simd = atoi(output+i); 
            }
            else if(strstr(output, "lds_size_in_kb")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("lds_size_in_kb=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.lds_size_in_kb = atoi(output+i); 
            }
            else if(strstr(output, "gds_size_in_kb")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("gds_size_in_kb=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.gds_size_in_kb = atoi(output+i); 
            }
            else if(strstr(output, "wave_front_size")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("wave_front_size=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.wave_front_size = atoi(output+i); 
            }
            else if(strstr(output, "array_count")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("array_count=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.array_count = atoi(output+i); 
            }
            else if(strstr(output, "simd_arrays_per_engine")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("simd_arrays_per_engine=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.simd_arrays_per_engine = atoi(output+i); 
            }
            else if(strstr(output, "cu_per_simd_array")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("cu_per_simd_array=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.cu_per_simd_array = atoi(output+i); 
            }
            else if(strstr(output, "simd_per_cu")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("simd_per_cu=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.simd_per_cu = atoi(output+i); 
            }
            else if(strstr(output, "max_slots_scratch_cu")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("max_slots_scratch_cu=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.max_slots_scratch_cu = atoi(output+i); 
            }
            else if(strstr(output, "engine_id")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("engine_id=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.engine_id = atoi(output+i); 
            }
            else if(strstr(output, "vendor_id")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("vendor_id=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.vendor_id = atoi(output+i); 
            }
            else if(strstr(output, "device_id")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("device_id=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.device_id = atoi(output+i); 
            }
            else if(strstr(output, "location_id")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("location_id=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.location_id = atoi(output+i); 
            }
            else if(strstr(output, "max_engine_clk_fcompute")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("max_engine_clk_fcompute=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.max_engine_clk_fcompute = atoi(output+i); 
            }
            else if(strstr(output, "local_mem_size")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("local_mem_size=%lld\n", atoll(output+i));
                sys_info.topology_device[node].node_properties.local_mem_size = atoll(output+i); 
            }
            else if(strstr(output, "max_engine_clk_ccompute")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("max_engine_clk_ccompute=%d\n", atoi(output+i));
                sys_info.topology_device[node].node_properties.max_engine_clk_ccompute = atoi(output+i); 
            }
/*            else if(strstr(output, "marketing_name")) {
                for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                printf("marketing_name=%ld\n", atoi(output+i));
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
        printf("cache count=%d\n", sys_info.topology_device[node].cache_count);
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
                    printf("processor_id_low=%d\n", atoi(output+i));
                    sys_info.topology_device[node].cache_properties[cache].processor_id_low = atoi(output+i); 
                }
                else if(strstr(output, "level")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("cache_level=%d\n", atoi(output+i));
                    sys_info.topology_device[node].cache_properties[cache].cache_level = atoi(output+i); 
                }
                else if(strstr(output, "cache_line_size")) {        // must before "size", because the strstr!
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("cacheline_size=%d\n", atoi(output+i));
                    sys_info.topology_device[node].cache_properties[cache].cacheline_size = atoi(output+i); 
                }
                else if(strstr(output, "size")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("cache_size=%d\n", atoi(output+i));
                    sys_info.topology_device[node].cache_properties[cache].cache_size = atoi(output+i); 
                }
                else if(strstr(output, "cache_lines_per_tag")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("cachelines_per_tag=%d\n", atoi(output+i));
                    sys_info.topology_device[node].cache_properties[cache].cachelines_per_tag = atoi(output+i); 
                }
                else if(strstr(output, "association")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("cache_assoc=%d\n", atoi(output+i));
                    sys_info.topology_device[node].cache_properties[cache].cache_assoc = atoi(output+i); 
                }
                else if(strstr(output, "latency")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("cache_latency=%d\n", atoi(output+i));
                    sys_info.topology_device[node].cache_properties[cache].cache_latency = atoi(output+i); 
                }
                else if(strstr(output, "type")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("cache_type=%d\n", atoi(output+i));
                    sys_info.topology_device[node].cache_properties[cache].cache_type = atoi(output+i); 
                }
                else if(strstr(output, "sibling_map")) {
                    char *num_base;
                    int index = 0;
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    num_base = output+i;
                    for(index=0; index<KFD_TOPOLOGY_CPU_SIBLINGS; index++) {
                        sys_info.topology_device[node].cache_properties[cache].sibling_map[index] = atoi(num_base);
                        for(; *num_base!=','; num_base++);
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
        printf("iolink count=%d\n", sys_info.topology_device[node].io_link_count);
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
        printf("membank count=%d\n", sys_info.topology_device[node].mem_bank_count);
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
                    printf("heap_type=%d\n", atoi(output+i));
                    sys_info.topology_device[node].mem_properties[membank].heap_type = atoi(output+i); 
                }
                else if(strstr(output, "size_in_bytes")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("size_in_bytes=%lld\n", atoll(output+i));
                    sys_info.topology_device[node].mem_properties[membank].size_in_bytes = atoll(output+i); 
                }
                else if(strstr(output, "flags")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("flags=%d\n", atoi(output+i));
                    sys_info.topology_device[node].mem_properties[membank].flags = atoi(output+i); 
                }
                else if(strstr(output, "width")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("width=%d\n", atoi(output+i));
                    sys_info.topology_device[node].mem_properties[membank].width = atoi(output+i); 
                }
                else if(strstr(output, "mem_clk_max")) {
                    for(i=0; !(output[i]>='0'&&output[i]<='9') && output[i]!='\0'; i++);
                    printf("mem_clk_max=%d\n", atoi(output+i));
                    sys_info.topology_device[node].mem_properties[membank].mem_clk_max = atoi(output+i); 
                }
                else {
                    printf("Known membank properties\n");
                }
            }
            pclose(fd);
        }
    }   // end for node loop

    struct virtkfd_sysfs_info *tmp = (struct virtkfd_sysfs_info*)param->iov_base; 
    iov_from_buf(param, 1, 0, &sys_info, sizeof(sys_info));

    return 1;
}

void virtio_kfd_handle_request(VirtIOKfdReq *req)
{
    uint32_t type;
    struct iovec *in_iov = req->elem.in_sg;
    struct iovec *iov = req->elem.out_sg;
    unsigned in_num = req->elem.in_num;
    unsigned out_num = req->elem.out_num;
    int ret;

    printf("virtio_kfd_handle_request ... in_num=%d out_num=%d\n", in_num, out_num);
    printf("out_iov[0]: base=%p, len=%d\n", iov[0].iov_base, iov[0].iov_len);
    printf("in_iov[0]: base=%p, len=%d\n", in_iov[0].iov_base, in_iov[0].iov_len);
    printf("in_iov[1]: base=%p, len=%d\n", in_iov[1].iov_base, in_iov[1].iov_len);

    if (req->elem.out_num < 1 || req->elem.in_num < 1) {
        error_report("virtio-kfd missing headers");
        exit(1);
    }

    if (unlikely(iov_to_buf(iov, out_num, 0, &req->out,         // copy vring data into req->out
                            sizeof(req->out)) != sizeof(req->out))) {
        error_report("virtio-kfd request outhdr too short");
        exit(1);
    }

    printf(" command=%d\n", req->out.cmd); 

//    iov_discard_front(&iov, &out_num, sizeof(req->out));

    if (in_num < 1 ||
        in_iov[in_num - 1].iov_len < sizeof(struct virtio_kfd_inhdr)) {
        error_report("virtio-kfd request inhdr too short");
        exit(1);
    }

    req->param = in_iov[0];
    req->in = (void *)in_iov[in_num - 1].iov_base
              + in_iov[in_num - 1].iov_len
              - sizeof(struct virtio_kfd_inhdr);
//    iov_discard_back(in_iov, &in_num, sizeof(struct virtio_kfd_inhdr));

    switch(req->out.cmd) {
    case VIRTKFD_GET_SYSINFO:
        printf("VIRTKFD_GET_SYSINFO\n");
        ret = virtkfd_get_sysinfo(&req->param);
        break;
    default:
        printf("Known command\n");
    }

    virtio_kfd_req_complete(req, VIRTIO_KFD_S_UNSUPP);
    virtio_kfd_free_request(req);
}

static void virtio_kfd_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOKfd *s = VIRTIO_KFD(vdev);
    VirtIOKfdReq *req;

    printf("virtio_kfd_handle_output\n");

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

    printf("virtio_kfd_device_realize\n");
    virtio_init(vdev, "virtio-kfd", VIRTIO_ID_KFD,
                sizeof(struct virtio_kfd_config));

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
