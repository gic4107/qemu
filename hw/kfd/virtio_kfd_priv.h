#ifndef VIRTIO_KFD_PRIV_H
#define VIRTIO_KFD_PRIV_H

#define KFD_TOPOLOGY_PUBLIC_NAME_SIZE 128
#define KFD_TOPOLOGY_CPU_SIBLINGS 256
#define PROPERTIES_NODE_MAX 5

// The command store inside virtqueue
#define VIRTKFD_GET_SYSINFO 1

/*
    This file must sync with virtio_kfd_priv.h
*/

struct virtkfd_system_properties {
    uint32_t    num_devices;        // not fill
    uint32_t    generation_count;
    uint64_t    platform_oem;
    uint64_t    platform_id;
    uint64_t    platform_rev;
};

struct virtkfd_node_properties {
    uint32_t cpu_cores_count;
    uint32_t simd_count;
    uint32_t mem_banks_count;
    uint32_t caches_count;
    uint32_t io_links_count;
    uint32_t cpu_core_id_base;
    uint32_t simd_id_base;
    uint32_t capability;
    uint32_t max_waves_per_simd;
    uint32_t lds_size_in_kb;
    uint32_t gds_size_in_kb;
    uint32_t wave_front_size;
    uint32_t array_count;
    uint32_t simd_arrays_per_engine;
    uint32_t cu_per_simd_array;
    uint32_t simd_per_cu;
    uint32_t max_slots_scratch_cu;
    uint32_t engine_id;
    uint32_t vendor_id;
    uint32_t device_id;
    uint32_t location_id;
    uint32_t max_engine_clk_fcompute;
    uint64_t local_mem_size;
    uint32_t max_engine_clk_ccompute;
    uint16_t marketing_name[KFD_TOPOLOGY_PUBLIC_NAME_SIZE];
};

struct virtkfd_mem_properties {
	uint32_t		heap_type;
	uint64_t		size_in_bytes;
	uint32_t		flags;
	uint32_t		width;
	uint32_t		mem_clk_max;
};

struct virtkfd_cache_properties {
	uint32_t		processor_id_low;
	uint32_t		cache_level;
	uint32_t		cache_size;
	uint32_t		cacheline_size;
	uint32_t		cachelines_per_tag;
	uint32_t		cache_assoc;
	uint32_t		cache_latency;
	uint32_t		cache_type;
	uint8_t			sibling_map[KFD_TOPOLOGY_CPU_SIBLINGS];
};

struct virtkfd_iolink_properties {
	uint32_t		iolink_type;
	uint32_t		ver_maj;
	uint32_t		ver_min;
	uint32_t		node_from;
	uint32_t		node_to;
	uint32_t		weight;
	uint32_t		min_latency;
	uint32_t		max_latency;
	uint32_t		min_bandwidth;
	uint32_t		max_bandwidth;
	uint32_t		rec_transfer_size;
	uint32_t		flags;
};

struct virtkfd_topology_device {
    uint32_t                         gpu_id;
    char                             name[100];
    uint32_t                         node_count;
    struct virtkfd_node_properties   node_properties[PROPERTIES_NODE_MAX];          // for node_show
	uint32_t			             mem_bank_count;
    struct virtkfd_mem_properties    mem_properties[PROPERTIES_NODE_MAX];          // for mem_show
	uint32_t			             cache_count;
    struct virtkfd_cache_properties  cache_properties[PROPERTIES_NODE_MAX];        // for kfd_cache_show
	uint32_t			             io_link_count;
    struct virtkfd_iolink_properties iolink_properties[PROPERTIES_NODE_MAX];       // for iolink_show
};

// Data structure to store host sysfs information
struct virtkfd_sysfs_info {
    struct virtkfd_system_properties system_properties;                             // for sysprops_show
    struct virtkfd_topology_device   topology_device;                               // for node_show
};

int virtio_kfd_topology_init(struct virtio_kfd *vkfd);
int virtkfd_add_req(struct virtio_kfd *vkfd, int *cmd, void *param, int param_len);
extern struct device* virtkfd_device;

#endif
