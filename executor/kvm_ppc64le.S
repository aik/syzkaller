// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// kvm_gen.cc generates machine code from this file and saves it into kvm.S.h.

// +build

#include "kvm.h"

#define LOAD64(rn,name)         \
    lis     rn,name##@highest;  \
    ori     rn,rn,name##@higher;    \
    rldicr  rn,rn,32,31;        \
    oris    rn,rn,name##@h;     \
    ori     rn,rn,name##@l

.global kvm_ppc64_mr, kvm_ppc64_mr_end
kvm_ppc64_mr:
	LOAD64(5, 0xbadc0de)
	mr      4,5
	mr      3,4
kvm_ppc64_mr_end:

.global kvm_ppc64_ld, kvm_ppc64_ld_end
kvm_ppc64_ld:
	LOAD64(15, 0xbadc0de)
	// 0x80 is unused area before the machine reset vector
	LOAD64(25, 0x80)
	std	15, 0(25)
	ld	3, 0(25)
kvm_ppc64_ld_end:

