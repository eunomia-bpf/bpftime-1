#include "bpf/bpf.h"
#include "bpf/libbpf_common.h"
#include "bpftime_shm.hpp"
#include "catch2/catch_test_macros.hpp"
#include "linux/bpf.h"
#include "spdlog/spdlog.h"
#include <boost/interprocess/creation_tags.hpp>
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <cstdint>
#include <handler/handler_manager.hpp>
#include <handler/map_handler.hpp>
#include <optional>
#include <unistd.h>

using boost::interprocess::managed_shared_memory;

const char *SHM_NAME = "bpftime_map_handler_test";

struct testable_map_def {
	bpftime::bpf_map_type map_type;
	std::optional<int> kernel_map_type;
	bool is_per_cpu = false;
	uint64_t extra_flags = 0;
	bool can_delete = true;
};

static testable_map_def testable_maps[] = {
	{
		.map_type = bpftime::bpf_map_type::BPF_MAP_TYPE_HASH,
	},
	{ .map_type = bpftime::bpf_map_type::BPF_MAP_TYPE_ARRAY,
	  .can_delete = false },
	{ .map_type = bpftime::bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY,
	  .is_per_cpu = true,
	  .can_delete = false },
	{ .map_type = bpftime::bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH,
	  .is_per_cpu = true },
	{ .map_type = bpftime::bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY,
	  .kernel_map_type = BPF_MAP_TYPE_ARRAY,
	  .extra_flags = BPF_F_MMAPABLE,
	  .can_delete = false },
	{ .map_type = bpftime::bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH,
	  .kernel_map_type = BPF_MAP_TYPE_HASH },
};

TEST_CASE("Test map handler")
{
	struct bpftime::shm_remove remover(SHM_NAME);
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);

	managed_shared_memory segment(boost::interprocess::create_only,
				      SHM_NAME, 20 << 20);
	auto manager = segment.construct<bpftime::handler_manager>(
		"handler_manager")(segment);
	auto &manager_ref = *manager;
	for (auto map_type : testable_maps) {
		SPDLOG_INFO("Testing map type {}", (int)map_type.map_type);
		struct kernel_map_tuple {
			uint32_t id;
			int fd;
		};
		std::optional<kernel_map_tuple> kernel_map_info;
		if (map_type.kernel_map_type) {
			LIBBPF_OPTS(bpf_map_create_opts, opts);
			opts.map_flags = map_type.extra_flags;
			int fd = bpf_map_create(
				(enum bpf_map_type)
					map_type.kernel_map_type.value(),
				"test_map", 4, 8, 1024, &opts);
			REQUIRE(fd > 0);
			struct bpf_map_info info;
			uint32_t len = sizeof(info);
			REQUIRE(bpf_map_get_info_by_fd(fd, &info, &len) == 0);
			kernel_map_info = {
				.id = info.id,
				.fd = fd,
			};
			SPDLOG_INFO("Created kernel map, fd={}, id={}", fd,
				    info.id);
		}
		manager_ref.set_handler(
			1,
			bpftime::bpf_map_handler(
				1, "test_map", segment,
				bpftime::bpf_map_attr{
					.type = (int)map_type.map_type,
					.key_size = 4,
					.value_size = 8,
					.max_ents = 1024,
					.kernel_bpf_map_id =
						kernel_map_info ?
							kernel_map_info->id :
							0 }),
			segment);

		auto &map = std::get<bpftime::bpf_map_handler>(manager_ref[1]);
		if (map_type.is_per_cpu) {
			REQUIRE(map.get_value_size() == (uint32_t)8 * ncpu);
		} else {
			REQUIRE(map.get_value_size() == 8);
		}
		int32_t key = 233;
		uint64_t value = 666;
		REQUIRE(map.map_update_elem(&key, &value, 0, false) == 0);
		if (map_type.is_per_cpu) {
			auto valueptr =
				(uint64_t *)map.map_lookup_elem(&key, true);
			REQUIRE(valueptr != nullptr);
			bool found = false;
			for (int i = 0; i < ncpu; i++) {
				if (valueptr[i] == value) {
					found = true;
					break;
				}
			}
			REQUIRE(found);
		} else {
			auto valueptr = map.map_lookup_elem(&key, false);
			REQUIRE(valueptr != nullptr);
			REQUIRE(*(uint64_t *)valueptr == value);
		}
		if (map_type.can_delete) {
			REQUIRE(map.map_delete_elem(&key) == 0);
			if (!map_type.is_per_cpu) {
				auto valueptr =
					map.map_lookup_elem(&key, false);
				REQUIRE(valueptr == nullptr);
			}
		}
		manager_ref.clear_id_at(1, segment);
		if (kernel_map_info) {
			close(kernel_map_info->id);
		}
	}
}
