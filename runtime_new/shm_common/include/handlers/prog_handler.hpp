#ifndef _PROG_HANDLER_HPP
#define _PROG_HANDLER_HPP
#include "spdlog/spdlog.h"
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <cstdint>
#include <utility>
#include <optional>
#include "handler_common_def.hpp"
namespace bpftime
{

namespace shm_common
{
using managed_shared_memory = boost::interprocess::managed_shared_memory;
using char_allocator = boost::interprocess::allocator<
	char, boost::interprocess::managed_shared_memory::segment_manager>;
using boost_shm_string =
	boost::interprocess::basic_string<char, std::char_traits<char>,
					  char_allocator>;

using cookie_fd_pair = std::pair<int, std::optional<uint64_t> >;

// bpf progs handler
// in share memory. This is only a simple data struct to store the
// bpf program data.
class bpf_prog_handler {
    public:
	/* Note that tracing related programs such as
	 * BPF_PROG_TYPE_{KPROBE,TRACEPOINT,PERF_EVENT,RAW_TRACEPOINT}
	 * are not subject to a stable API since kernel internal data
	 * structures can change from release to release and may
	 * therefore break existing tracing BPF programs. Tracing BPF
	 * programs correspond to /a/ specific kernel which is to be
	 * analyzed, and not /a/ specific kernel /and/ all future ones.
	 */
	bpf_prog_type type;

	bpf_prog_handler(managed_shared_memory &mem,
			 const void *insn, size_t insn_cnt,
			 const char *prog_name, int prog_type);
	bpf_prog_handler(const bpf_prog_handler &) = delete;
	bpf_prog_handler(bpf_prog_handler &&) noexcept = default;
	bpf_prog_handler &operator=(const bpf_prog_handler &) = delete;
	bpf_prog_handler &operator=(bpf_prog_handler &&) noexcept = default;

	using shm_ebpf_inst_vector_allocator = boost::interprocess::allocator<
		uint64_t, managed_shared_memory::segment_manager>;

	using inst_vector =
		boost::interprocess::vector<uint64_t,
					    shm_ebpf_inst_vector_allocator>;
	inst_vector insns;

	using shm_pair_vector_allocator = boost::interprocess::allocator<
		cookie_fd_pair, managed_shared_memory::segment_manager>;

	using attach_fds_vector =
		boost::interprocess::vector<cookie_fd_pair,
					    shm_pair_vector_allocator>;
	mutable attach_fds_vector attach_fds;

	void add_attach_fd(int fd, std::optional<uint64_t> cookie) const
	{
		SPDLOG_DEBUG("Add attach fd {} for bpf_prog {}", fd,
			     name.c_str());
		attach_fds.emplace_back(fd, cookie);
	}
	boost_shm_string name;
};
} // namespace shm_common

} // namespace bpftime

#endif