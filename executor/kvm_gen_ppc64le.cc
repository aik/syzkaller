// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#include <stdio.h>

#define PRINT(x)                                    \
	extern const unsigned char(x)[], x##_end[]; \
	print(#x, x, x##_end);

void print(const char* name, const unsigned char* start, const unsigned char* end)
{
	printf("const char %s[] = \"", name);
	for (const unsigned char* p = start; p < end; p++)
		printf("\\x%02x", *p);
	printf("\";\n");
}

int main()
{
	printf("// Code generated by executor/kvm_gen.cc. DO NOT EDIT.\n");
	PRINT(kvm_ppc64_mr);
	PRINT(kvm_ppc64_ld);
	return 0;
}
