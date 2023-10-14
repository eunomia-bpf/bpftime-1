#ifndef _BPFTIME_PER_CPU_ARRAY_MAP_HPP
#define _BPFTIME_PER_CPU_ARRAY_MAP_HPP
#include "bpf_map/array_map.hpp"
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/smart_ptr/unique_ptr.hpp>
#include <boost/interprocess/containers/vector.hpp>

#include <cstdint>
namespace bpftime
{

using array_map_vec_allocator = boost::interprocess::allocator<
	array_map_impl,
	boost::interprocess::managed_shared_memory::segment_manager>;
using array_map_vec =
	boost::interprocess::vector<array_map_impl, array_map_vec_allocator>;
class per_cpu_array_map_impl {
	array_map_vec impl;

    public:
	const static bool should_lock = false;

	per_cpu_array_map_impl(
		boost::interprocess::managed_shared_memory &memory,
		uint32_t value_size, uint32_t max_entries);

	void *elem_lookup(const void *key);

	long elem_update(const void *key, const void *value, uint64_t flags);

	long elem_delete(const void *key);

	int bpf_map_get_next_key(const void *key, void *next_key);
};
} // namespace bpftime

#endif