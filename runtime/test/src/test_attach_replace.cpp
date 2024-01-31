/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include <stdio.h>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <assert.h>
#include <inttypes.h>
#include "bpftime.hpp"
#include "bpftime_object.hpp"
#include "test_defs.h"
#include "bpftime_shm.hpp"
#include "bpftime_ufunc.hpp"
#include "attach/attach_manager/base_attach_manager.hpp"

extern "C" uint64_t bpftime_set_retval(uint64_t value);

using namespace bpftime;

// This is the original function to hook.
int my_function(int parm1, const char *str, char c)
{
	printf("origin func: Args: %d, %s, %c\n", parm1, str, c);
	return 35;
}

const char *obj_path = "./replace.bpf.o";

static void register_ufunc_for_print_and_add(bpf_attach_ctx *probe_ctx)
{
	ebpf_ufunc_func_info func2 = { "add_func",
				       UFUNC_FN(add_func),
				       UFUNC_TYPE_INT32,
				       { UFUNC_TYPE_INT32, UFUNC_TYPE_INT32 },
				       2,
				       0,
				       false };
	bpftime_ufunc_resolve_from_info(&probe_ctx->get_attach_manager(),
					func2);

	ebpf_ufunc_func_info func1 = { "print_func",
				       UFUNC_FN(print_func),
				       UFUNC_TYPE_INT64,
				       { UFUNC_TYPE_POINTER },
				       1,
				       0,
				       false };
	bpftime_ufunc_resolve_from_info(&probe_ctx->get_attach_manager(),
					func1);
}

int main()
{
	int res = 1;

	// test for no attach
	res = my_function(1, "hello aaa", 'c');
	printf("origin func return: %d\n", res);
	assert(res == 35);

	bpf_attach_ctx probe_ctx;
	register_ufunc_for_print_and_add(&probe_ctx);
	bpftime_object *obj = bpftime_object_open(obj_path);
	assert(obj);
	// get the first program
	bpftime_prog *prog = bpftime_object__next_program(obj, NULL);
	assert(prog);
	// add ufunc support
	res = bpftime_helper_group::get_ufunc_helper_group()
		      .add_helper_group_to_prog(prog);
	assert(res == 0);
	res = prog->bpftime_prog_load(false);
	assert(res == 0);
	// attach
	int fd = probe_ctx.get_attach_manager().attach_uprobe_override_at(
		(void *)my_function, [=](const pt_regs &regs) {
			uint64_t ret;
			prog->bpftime_prog_exec((void *)&regs, sizeof(regs),
						&ret);
			bpftime_set_retval(ret);
		});
	assert(fd >= 0);

	// test for attach
	res = my_function(1, "hello aaa", 'c');
	printf("hooked func return: %d\n", res);
	assert(res == 100);

	// detach
	res = probe_ctx.get_attach_manager().destroy_attach(fd);
	assert(res == 0);

	// test for no attach
	res = my_function(1, "hello aaa", 'c');
	printf("origin func return: %d\n", res);
	assert(res == 35);

	bpftime_object_close(obj);

	return 0;
}
