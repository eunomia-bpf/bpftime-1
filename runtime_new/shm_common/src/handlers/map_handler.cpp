/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include "maps/userspace/per_cpu_array_map.hpp"
#include "maps/userspace/per_cpu_hash_map.hpp"
#include "utils/bpftime_lock_guard.hpp"
#include <maps/userspace/perf_event_array_map.hpp>
#include "spdlog/spdlog.h"
#include <handlers/map_handler.hpp>
#include <maps/userspace/array_map.hpp>
#include <maps/userspace/hash_map.hpp>
#include <maps/userspace/ringbuf_map.hpp>
#include <maps/shared/array_map_kernel_user.hpp>
#include <maps/shared/hash_map_kernel_user.hpp>
#include <maps/shared/percpu_array_map_kernel_user.hpp>
#include <maps/shared/perf_event_array_kernel_user.hpp>
#include <maps/userspace/prog_array.hpp>
#include <unistd.h>

using boost::interprocess::interprocess_sharable_mutex;
using boost::interprocess::scoped_lock;
using boost::interprocess::sharable_lock;

namespace bpftime
{
namespace shm_common
{
uint32_t bpf_map_handler::get_userspace_value_size() const
{
	auto result = value_size;
	if ((type == bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY) ||
	    (type == bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH)) {
		result *= sysconf(_SC_NPROCESSORS_ONLN);
	}
	return result;
}
std::optional<ringbuf_map_impl *>
bpf_map_handler::try_get_ringbuf_map_impl() const
{
	if (type != bpf_map_type::BPF_MAP_TYPE_RINGBUF)
		return {};
	return static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
}
std::optional<array_map_impl *> bpf_map_handler::try_get_array_map_impl() const
{
	if (type != bpf_map_type::BPF_MAP_TYPE_ARRAY)
		return {};
	return static_cast<array_map_impl *>(map_impl_ptr.get());
}

const void *bpf_map_handler::map_lookup_elem(const void *key,
					     bool from_userspace) const
{
	const auto do_lookup = [&](auto *impl) -> const void * {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_lookup(key);
		} else {
			return impl->elem_lookup(key);
		}
	};
	const auto do_lookup_userspace = [&](auto *impl) -> const void * {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_lookup_userspace(key);
		} else {
			return impl->elem_lookup_userspace(key);
		}
	};

	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		auto impl = static_cast<hash_map_impl *>(map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		auto impl = static_cast<array_map_impl *>(map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto impl = static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_map_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		auto impl = static_cast<per_cpu_array_map_impl *>(
			map_impl_ptr.get());
		return from_userspace ? do_lookup_userspace(impl) :
					do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		auto impl = static_cast<per_cpu_hash_map_impl *>(
			map_impl_ptr.get());
		return from_userspace ? do_lookup_userspace(impl) :
					do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		auto impl = static_cast<array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		auto impl = static_cast<hash_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		auto impl = static_cast<percpu_array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		auto impl =
			static_cast<prog_array_map_impl *>(map_impl_ptr.get());
		return do_lookup(impl);
	}
	default:
		assert(false && "Unsupported map type");
	}
	return 0;
}

long bpf_map_handler::map_update_elem(const void *key, const void *value,
				      uint64_t flags, bool from_userspace) const
{
	const auto do_update = [&](auto *impl) -> long {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_update(key, value, flags);
		} else {
			return impl->elem_update(key, value, flags);
		}
	};

	const auto do_update_userspace = [&](auto *impl) -> long {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_update_userspace(key, value, flags);
		} else {
			return impl->elem_update_userspace(key, value, flags);
		}
	};
	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		auto impl = static_cast<hash_map_impl *>(map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		auto impl = static_cast<array_map_impl *>(map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto impl = static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_map_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		auto impl = static_cast<per_cpu_array_map_impl *>(
			map_impl_ptr.get());
		return from_userspace ? do_update_userspace(impl) :
					do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		auto impl = static_cast<per_cpu_hash_map_impl *>(
			map_impl_ptr.get());
		return from_userspace ? do_update_userspace(impl) :
					do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		auto impl = static_cast<array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		auto impl = static_cast<hash_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		auto impl = static_cast<percpu_array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		auto impl =
			static_cast<prog_array_map_impl *>(map_impl_ptr.get());
		return do_update(impl);
	}
	default:
		assert(false && "Unsupported map type");
	}
	return 0;
}

int bpf_map_handler::bpf_map_get_next_key(const void *key, void *next_key,
					  bool from_userspace) const
{
	const auto do_get_next_key = [&](auto *impl) -> int {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->map_get_next_key(key, next_key);
		} else {
			return impl->map_get_next_key(key, next_key);
		}
	};
	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		auto impl = static_cast<hash_map_impl *>(map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		auto impl = static_cast<array_map_impl *>(map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto impl = static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_map_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		auto impl = static_cast<per_cpu_array_map_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		auto impl = static_cast<per_cpu_hash_map_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		auto impl = static_cast<array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		auto impl = static_cast<hash_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		auto impl = static_cast<percpu_array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		auto impl =
			static_cast<prog_array_map_impl *>(map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	default:
		assert(false && "Unsupported map type");
	}
	return 0;
}

long bpf_map_handler::map_delete_elem(const void *key,
				      bool from_userspace) const
{
	const auto do_delete = [&](auto *impl) -> long {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_delete(key);
		} else {
			return impl->elem_delete(key);
		}
	};
	const auto do_delete_userspace = [&](auto *impl) -> long {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_delete_userspace(key);
		} else {
			return impl->elem_delete_userspace(key);
		}
	};

	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		auto impl = static_cast<hash_map_impl *>(map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		auto impl = static_cast<array_map_impl *>(map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto impl = static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_map_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		auto impl = static_cast<per_cpu_array_map_impl *>(
			map_impl_ptr.get());
		return from_userspace ? do_delete_userspace(impl) :
					do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		auto impl = static_cast<per_cpu_hash_map_impl *>(
			map_impl_ptr.get());
		return from_userspace ? do_delete_userspace(impl) :
					do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		auto impl = static_cast<array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		auto impl = static_cast<hash_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		auto impl = static_cast<percpu_array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		auto impl =
			static_cast<prog_array_map_impl *>(map_impl_ptr.get());
		return do_delete(impl);
	}
	default:
		assert(false && "Unsupported map type");
	}
	return 0;
}

int bpf_map_handler::map_init(boost::interprocess::managed_shared_memory &memory)
{
	using boost::interprocess::anonymous_instance;
	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		map_impl_ptr = memory.construct<hash_map_impl>(
			anonymous_instance)(memory, key_size, value_size);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		map_impl_ptr = memory.construct<array_map_impl>(
			anonymous_instance)(memory, value_size, max_entries);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto max_ent = max_entries;
		int pop_cnt = 0;
		while (max_ent) {
			pop_cnt += (max_ent & 1);
			max_ent >>= 1;
		}
		if (pop_cnt != 1) {
			SPDLOG_ERROR(
				"Failed to create ringbuf map, max_entries must be a power of 2, current: {}",
				max_entries);
			return -1;
		}
		map_impl_ptr = memory.construct<ringbuf_map_impl>(
			anonymous_instance)(max_entries, memory);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		map_impl_ptr = memory.construct<perf_event_array_map_impl>(
			anonymous_instance)(memory, key_size, value_size,
					    max_entries);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		map_impl_ptr = memory.construct<per_cpu_array_map_impl>(
			anonymous_instance)(memory, value_size, max_entries);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		map_impl_ptr = memory.construct<per_cpu_hash_map_impl>(
			anonymous_instance)(memory, key_size, value_size);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		map_impl_ptr = memory.construct<array_map_kernel_user_impl>(
			anonymous_instance)(memory, attr.kernel_bpf_map_id);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		map_impl_ptr = memory.construct<hash_map_kernel_user_impl>(
			anonymous_instance)(memory, attr.kernel_bpf_map_id);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		map_impl_ptr =
			memory.construct<percpu_array_map_kernel_user_impl>(
				anonymous_instance)(memory,
						    attr.kernel_bpf_map_id);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		map_impl_ptr =
			memory.construct<perf_event_array_kernel_user_impl>(
				anonymous_instance)(
				memory, 4, 4, sysconf(_SC_NPROCESSORS_ONLN),
				attr.kernel_bpf_map_id);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		map_impl_ptr = memory.construct<prog_array_map_impl>(
			anonymous_instance)(memory, key_size, value_size,
					    max_entries);
		return 0;
	}

	default:
		SPDLOG_ERROR("Unsupported map type: {}", (int)type);
		// assert(false && "Unsupported map type");
		return -1;
	}
	return 0;
}

void bpf_map_handler::map_free(
	boost::interprocess::managed_shared_memory &memory)
{
	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH:
		memory.destroy_ptr<hash_map_impl>(
			(hash_map_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_ARRAY:
		memory.destroy_ptr<array_map_impl>(
			(array_map_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF:
		memory.destroy_ptr<ringbuf_map_impl>(
			(ringbuf_map_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		memory.destroy_ptr<perf_event_array_map_impl>(
			(perf_event_array_map_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY:
		memory.destroy_ptr<per_cpu_array_map_impl>(
			(per_cpu_array_map_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH:
		memory.destroy_ptr<per_cpu_hash_map_impl>(
			(per_cpu_hash_map_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY:
		memory.destroy_ptr<array_map_kernel_user_impl>(
			(array_map_kernel_user_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH:
		memory.destroy_ptr<hash_map_kernel_user_impl>(
			(hash_map_kernel_user_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY:
		memory.destroy_ptr<percpu_array_map_kernel_user_impl>(
			(percpu_array_map_kernel_user_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY:
		memory.destroy_ptr<perf_event_array_kernel_user_impl>(
			(perf_event_array_kernel_user_impl *)map_impl_ptr.get());
		break;
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY:
		memory.destroy_ptr<prog_array_map_impl>(
			(prog_array_map_impl *)map_impl_ptr.get());
		break;

	default:
		assert(false && "Unsupported map type");
	}
	map_impl_ptr = nullptr;
	return;
}
std::optional<perf_event_array_kernel_user_impl *>
bpf_map_handler::try_get_shared_perf_event_array_map_impl() const
{
	if (type != bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY)
		return {};
	return static_cast<perf_event_array_kernel_user_impl *>(
		map_impl_ptr.get());
}

} // namespace shm_common
} // namespace bpftime
