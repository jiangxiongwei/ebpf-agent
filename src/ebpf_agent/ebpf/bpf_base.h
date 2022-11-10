/*
 * Copyright (c) 2022 Perfma
 *
 */


#ifndef __BPF_BASE_H__
#define __BPF_BASE_H__



#define NAME(N)  __##N

#define MAP_PERARRAY(name, key_type, value_type, max_entries) \
struct { \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
    __BPF_MAP_DEF(key_type, value_type, max_entries); \
}  __##name SEC(".maps"); \
static __always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static __always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static __always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
{ \
    return bpf_map_delete_elem(& __##name, (const void *)key); \
}



#define MAP_HASH(name, key_type, value_type, max_entries) \
struct { \
    __uint(type, BPF_MAP_TYPE_HASH); \
    __BPF_MAP_DEF(key_type, value_type, max_entries); \
} __##name SEC(".maps"); \
static __always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static __always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static __always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
{ \
    return bpf_map_delete_elem(& __##name, (const void *)key); \
}



#endif /* __BPF_BASE_H__ */