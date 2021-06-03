// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.
// See Intel Software Developer’s Manual Volume 3: System Programming Guide
// for details on what happens here.

#include "kvm.h"

#define BITS_PER_LONG 64
#define PPC_BITLSHIFT(be) (BITS_PER_LONG - 1 - (be))
#define PPC_BIT(bit) (1ULL << PPC_BITLSHIFT(bit))
#define PPC_BITMASK(bs, be) ((PPC_BIT(bs) - PPC_BIT(be)) | PPC_BIT(bs))

#define RADIX_PTE_INDEX_SIZE 5 // size: 8B <<  5 = 256B, maps 2^5  x   64K =   2MB
#define RADIX_PMD_INDEX_SIZE 9 // size: 8B <<  9 =  4KB, maps 2^9  x   2MB =   1GB
#define RADIX_PUD_INDEX_SIZE 9 // size: 8B <<  9 =  4KB, maps 2^9  x   1GB = 512GB
#define RADIX_PGD_INDEX_SIZE 13 // size: 8B << 13 = 64KB, maps 2^13 x 512GB =   4PB

#define cpu_to_be32(x) __builtin_bswap32(x)
#define cpu_to_be64(x) __builtin_bswap64(x)

#define KVM_SETUP_PAGING (1 << 0)
#define KVM_SETUP_PPC64_PR (1 << 3)
#define KVM_SETUP_PPC64_LE (1 << 16)

#define ALIGNUP(p, q) ((void*)(((unsigned long)(p) + (q)-1) & ~((q)-1)))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

static int kvmppc_define_rtas_kernel_token(int vmfd, unsigned token, const char* func)
{
	struct kvm_rtas_token_args args;

	args.token = token;
	strncpy(args.name, func, sizeof(args.name) - 1);

	return ioctl(vmfd, KVM_PPC_RTAS_DEFINE_TOKEN, &args);
}

// syz_kvm_setup_cpu(fd fd_kvmvm, cpufd fd_kvmcpu, usermem vma[24], text ptr[in, array[kvm_text, 1]], ntext len[text], flags flags[kvm_setup_flags_ppc64], opts ptr[in, array[kvm_setup_opt, 0:2]], nopt len[opts])
static long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	const int vmfd = a0;
	const int cpufd = a1;
	char* const host_mem = (char*)a2;
	const struct kvm_text* const text_array_ptr = (struct kvm_text*)a3;
	const uintptr_t text_count = a4;
	const uintptr_t flags = a5;
	const uintptr_t page_size = 16 << 10;
	const uintptr_t guest_mem_size = 256 << 20;
	const uintptr_t guest_mem = 0;
	unsigned long gpa_off = 0;

	(void)text_count; // fuzzer can spoof count and we need just 1 text, so ignore text_count
	const void* text = 0;
	uintptr_t text_size = 0;
	NONFAILING(text = text_array_ptr[0].text);
	NONFAILING(text_size = text_array_ptr[0].size);

	for (uintptr_t i = 0; i < guest_mem_size / page_size; i++) {
		struct kvm_userspace_memory_region memreg;
		memreg.slot = i;
		memreg.flags = 0; // can be KVM_MEM_LOG_DIRTY_PAGES | KVM_MEM_READONLY
		memreg.guest_phys_addr = guest_mem + i * page_size;
		memreg.memory_size = page_size;
		memreg.userspace_addr = (uintptr_t)host_mem + i * page_size;
		ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg);
	}

	struct kvm_regs regs;
	struct kvm_sregs sregs;
	if (ioctl(cpufd, KVM_GET_SREGS, &sregs))
		return -1;
	if (ioctl(cpufd, KVM_GET_REGS, &regs))
		return -1;

	regs.msr = PPC_BIT(63); // MSR_SF == 64bit
	if (flags & KVM_SETUP_PPC64_LE)
		PPC_BIT(63); // Little endian

	/* PR == "problem state" == non priveledged */
	if (flags & KVM_SETUP_PPC64_PR)
		PPC_BIT(49);

	if (flags & KVM_SETUP_PAGING) {
		/* Set up a page table */
		struct prtb_entry {
			__be64 prtb0;
			__be64 prtb1;
		} * process_tb;
		unsigned long *pgd, *pud, *pmd, *pte, i;
		struct kvm_ppc_mmuv3_cfg cfg = {
		    .flags = KVM_PPC_MMUV3_RADIX | KVM_PPC_MMUV3_GTSE,
		    .process_table = gpa_off,
		};
		const long max_shift = 52;
		const unsigned long rts = (((max_shift - 31) >> 3) << PPC_BITLSHIFT(2)) |
					  (((max_shift - 31) & 7) << PPC_BITLSHIFT(58));

		regs.msr |= PPC_BIT(58) | // IR - MMU=on for instructions
			    PPC_BIT(59); // DR - MMU=on for data

		gpa_off += page_size; // Skip page at 0.
		process_tb = (struct prtb_entry*)(host_mem + gpa_off);
		gpa_off += page_size;
		pgd = (unsigned long*)(host_mem + gpa_off);
		gpa_off += page_size;
		pud = (unsigned long*)(host_mem + gpa_off);
		gpa_off += page_size;
		pmd = (unsigned long*)(host_mem + gpa_off);
		gpa_off += page_size;
		pte = (unsigned long*)(host_mem + gpa_off);
		for (i = 0; i < MAX(1, (text_size / page_size) >> RADIX_PTE_INDEX_SIZE); ++i)
			gpa_off += page_size;

		memset(host_mem, 0, gpa_off);

		regs.pc = gpa_off;

		process_tb[0].prtb0 = cpu_to_be64(rts | (unsigned long)pgd | RADIX_PGD_INDEX_SIZE);

		pgd[0] = cpu_to_be64(PPC_BIT(0) | // Valid
				     ((unsigned long)pud & PPC_BITMASK(4, 55)) |
				     RADIX_PUD_INDEX_SIZE);
		pud[0] = cpu_to_be64(PPC_BIT(0) | // Valid
				     ((unsigned long)pmd & PPC_BITMASK(4, 55)) |
				     RADIX_PMD_INDEX_SIZE);
		pmd[0] = cpu_to_be64(PPC_BIT(0) | // Valid
				     ((unsigned long)pte & PPC_BITMASK(4, 55)) |
				     RADIX_PTE_INDEX_SIZE);

		for (i = 0; i < text_size / page_size; ++i, gpa_off += page_size) {
			unsigned long *ptes, *ptep;

			ptes = (unsigned long*)((char*)pte + (i >> RADIX_PTE_INDEX_SIZE) * page_size);

			ptep = &ptes[i & ~(1UL << RADIX_PTE_INDEX_SIZE)];
			*ptep = cpu_to_be64(PPC_BIT(0) | // Valid
					    PPC_BIT(1) | // Leaf
					    (gpa_off & PPC_BITMASK(7, 51)) |
					    PPC_BIT(61) | // Read: 1 - loads permitted
					    PPC_BIT(63)); // Execute: 1 - instruction execution permitted
		}

		if (ioctl(vmfd, KVM_PPC_CONFIGURE_V3_MMU, &cfg))
			return -1;
	}

	memcpy(host_mem + gpa_off, text, text_size);

	// The code generator produces little endian instructions so swap bytes here
	if (!(flags & KVM_SETUP_PPC64_LE)) {
		uint32_t* p = (uint32_t*)(host_mem + gpa_off);

		for (unsigned long i = 0; i < text_size / sizeof(*p); ++i)
			p[i] = cpu_to_be32(p[i]);
	}

	if (ioctl(cpufd, KVM_SET_SREGS, &sregs))
		return -1;
	if (ioctl(cpufd, KVM_SET_REGS, &regs))
		return -1;

		// Hypercalls need to be enable so we enable them all here to
		// allow fuzzing
#define MAX_HCALL 0x450
	for (unsigned hcall = 4; hcall < MAX_HCALL; hcall += 4) {
		struct kvm_enable_cap cap = {
		    .cap = KVM_CAP_PPC_ENABLE_HCALL,
		    .flags = 0,
		    .args = {hcall, 1},
		};
		ioctl(vmfd, KVM_ENABLE_CAP, &cap);
	}

	/*
	 * Only a few of many RTAS calls are actually in the KVM and the rest
	 * are handled in QEMU, enable the KVM handling for those 4 here.
	 */
	kvmppc_define_rtas_kernel_token(vmfd, 1, "ibm,set-xive");
	kvmppc_define_rtas_kernel_token(vmfd, 2, "ibm,get-xive");
	kvmppc_define_rtas_kernel_token(vmfd, 3, "ibm,int-on");
	kvmppc_define_rtas_kernel_token(vmfd, 4, "ibm,int-off");

	return 0;
}
