#include "spdlog/spdlog.h"
#include <boost/interprocess/detail/segment_manager_helper.hpp>
#include <boost/interprocess/smart_ptr/shared_ptr.hpp>
#include <handler/perf_event_handler.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <unistd.h>


namespace bpftime
{
// attach to replace or filter self define types
bpf_perf_event_handler::bpf_perf_event_handler(
	bpf_event_type type, uint64_t offset, int pid, const char *module_name,
	boost::interprocess::managed_shared_memory &mem)
	: type(type), offset(offset), pid(pid),
	  _module_name(char_allocator(mem.get_segment_manager()))
{
	this->_module_name = module_name;
}
// create uprobe/uretprobe with new perf event attr
bpf_perf_event_handler::bpf_perf_event_handler(
	bool is_retprobe, uint64_t offset, int pid, const char *module_name,
	size_t ref_ctr_off, boost::interprocess::managed_shared_memory &mem)
	: offset(offset), pid(pid), ref_ctr_off(ref_ctr_off),
	  _module_name(char_allocator(mem.get_segment_manager()))
{
	if (is_retprobe) {
		type = bpf_event_type::BPF_TYPE_URETPROBE;
	} else {
		type = bpf_event_type::BPF_TYPE_UPROBE;
	}
	this->_module_name = module_name;
}

// create tracepoint
bpf_perf_event_handler::bpf_perf_event_handler(
	int pid, int32_t tracepoint_id,
	boost::interprocess::managed_shared_memory &mem)
	: type(bpf_event_type::PERF_TYPE_TRACEPOINT), pid(pid),
	  _module_name(char_allocator(mem.get_segment_manager())),
	  tracepoint_id(tracepoint_id)
{
}

bpf_perf_event_handler::bpf_perf_event_handler(
	int cpu, int32_t sample_type, int64_t config,
	boost::interprocess::managed_shared_memory &mem)
	: type(bpf_event_type::PERF_TYPE_SOFTWARE),
	  _module_name(char_allocator(mem.get_segment_manager())),
	  sw_perf(boost::interprocess::make_managed_shared_ptr(
		  mem.construct<software_perf_event_data>(
			  boost::interprocess::anonymous_instance)(
			  cpu, config, sample_type, mem),
		  mem))

{
}
int software_perf_event_data::output_data(const void *buf, size_t size)
{
}
perf_event_mmap_page &software_perf_event_data::get_header_ref()
{
	return *(perf_event_mmap_page *)(uintptr_t)(mmap_buffer.data());
}

software_perf_event_data::software_perf_event_data(
	int cpu, int64_t config, int32_t sample_type,
	boost::interprocess::managed_shared_memory &memory)
	: cpu(cpu), config(config), sample_type(sample_type),
	  pagesize(getpagesize()),
	  mmap_buffer(pagesize, memory.get_segment_manager())
{
	perf_event_mmap_page &perf_header = get_header_ref();
	perf_header.data_offset = pagesize;
	perf_header.data_head = perf_header.data_tail = 0;
	perf_header.data_size = 0;
}
void *software_perf_event_data::ensure_mmap_buffer(size_t buffer_size)
{
	if (buffer_size > mmap_buffer.size()) {
		spdlog::debug("Expanding mmap buffer size to {}", buffer_size);
		mmap_buffer.resize(buffer_size);
		// Update data size in the mmap header
		get_header_ref().data_size = buffer_size - pagesize;
	}
	return mmap_buffer.data();
}
size_t software_perf_event_data::mmap_size() const
{
	return mmap_buffer.size() - pagesize;
}
std::optional<software_perf_event_weak_ptr>
bpf_perf_event_handler::try_get_software_perf_data_weak_ptr() const
{
	if (sw_perf.has_value()) {
		return software_perf_event_weak_ptr(sw_perf.value());
	} else {
		return {};
	}
}

std::optional<void *>
bpf_perf_event_handler::try_get_software_perf_data_raw_buffer(
	size_t buffer_size) const
{
	if (sw_perf.has_value()) {
		return sw_perf.value()->ensure_mmap_buffer(buffer_size);
	} else {
		return {};
	}
}
} // namespace bpftime
