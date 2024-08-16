#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("uprobe/benchmark/test:__bench_write")
int BPF_UPROBE(__bench_write, char *a, int b, uint64_t c)
{
	char buffer[5] = "text";
	bpf_probe_write_user(a, buffer, sizeof(buffer));
	return b + c;
}

SEC("uprobe/benchmark/test:__bench_read")
int BPF_UPROBE(__bench_read, char *a, int b, uint64_t c)
{
	char buffer[5];
	int res = bpf_probe_read_user(buffer, sizeof(buffer), a);
	return b + c + res + buffer[1];
}

SEC("uprobe/benchmark/test:__bench_uprobe")
int BPF_UPROBE(__bench_uprobe, char *a, int b, uint64_t c)
{
	return b + c;
}

SEC("uretprobe/benchmark/test:__bench_uretprobe")
int BPF_URETPROBE(__bench_uretprobe, int ret)
{
	return ret;
}

SEC("uprobe/benchmark/test:__bench_uprobe_uretprobe")
int BPF_UPROBE(__bench_uprobe_uretprobe_1, char *a, int b, uint64_t c)
{
	return b + c;
}

SEC("uretprobe/benchmark/test:__bench_uprobe_uretprobe")
int BPF_URETPROBE(__benchmark_test_function_1_2, int ret)
{
	return ret;
}

char LICENSE[] SEC("license") = "GPL";
