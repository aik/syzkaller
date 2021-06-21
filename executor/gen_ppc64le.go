// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build ppc64le,!freebsd,!darwin,!openbsd,!netbsd

//go:generate bash -c "gcc kvm_gen_ppc64le.cc kvm_ppc64le.S -o kvm_gen && ./kvm_gen > kvm_ppc64le.S.h && rm ./kvm_gen"

package executor
