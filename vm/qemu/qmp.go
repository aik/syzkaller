// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"bufio"
	"debug/elf"
	"encoding/json"
	"fmt"
	"math/bits"
	"net"
	"strings"

	"github.com/google/syzkaller/pkg/log"
)

type qmpCommand struct {
	Execute   string      `json:"execute"`
	Arguments interface{} `json:"arguments,omitempty"`
}

type hmpCommand struct {
	Command string `json:"command-line"`
	CPU     int    `json:"cpu-index"`
}

type qmpResponse struct {
	Error struct {
		Class string
		Desc  string
	}
	Return interface{}
}

type qmpEvent struct {
	Event     string
	Data      map[string]interface{}
	Timestamp struct {
		Seconds      int64
		Microseconds int64
	}
}

func (inst *instance) qmpConnCheck() error {
	if inst.mon != nil {
		return nil
	}

	addr := fmt.Sprintf("127.0.0.1:%v", inst.monport)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(conn)
	monEnc := json.NewEncoder(conn)

	inst.mon = conn
	inst.scanner = scanner

	inst.qmpRecv()

	inst.monEnc = monEnc
	if _, err := inst.doQmp(&qmpCommand{Execute: "qmp_capabilities"}); err != nil {
		inst.monEnc = nil
		inst.mon = nil
		inst.scanner = nil
		return err
	}

	return nil
}

func (inst *instance) qmpRecv() (*qmpResponse, error) {
	qmp := new(qmpResponse)
	var err error

	for inst.scanner.Scan() {
		var qe qmpEvent
		b := inst.scanner.Bytes()
		err = json.Unmarshal(b, &qe)
		if err != nil {
			continue
		}
		if qe.Event == "" {
			err = json.Unmarshal(b, qmp)
			if err != nil {
				continue
			} else {
				break
			}
		}
		log.Logf(0, "skipping event: %+v", qe)
	}

	return qmp, err
}

func (inst *instance) doQmp(cmd *qmpCommand) (*qmpResponse, error) {
	if err := inst.monEnc.Encode(cmd); err != nil {
		return nil, err
	}
	return inst.qmpRecv()
}

func (inst *instance) qmp(cmd *qmpCommand) (interface{}, error) {
	if err := inst.qmpConnCheck(); err != nil {
		return nil, err
	}
	resp, err := inst.doQmp(cmd)
	if err != nil {
		return nil, err
	}
	if resp.Error.Desc != "" {
		return resp.Return, fmt.Errorf("error %v", resp.Error)
	}
	if resp.Return == nil {
		return nil, fmt.Errorf(`no "return" nor "error" in [%v]`, resp)
	}
	return resp.Return, nil
}

func (inst *instance) hmp(cmd string, cpu int) (string, error) {
	req := &qmpCommand{
		Execute: "human-monitor-command",
		Arguments: &hmpCommand{
			Command: cmd,
			CPU:     cpu,
		},
	}
	resp, err := inst.qmp(req)
	if err != nil {
		return "", err
	}
	return resp.(string), nil
}

// The offets calculated below are from:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/printk/printk.c?h=v5.10#n436
//
// This caches certain offsets in the lockless printk ringbuffer introduced in
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=896fbe20b4e2333f
//
// Before 896fbe20b4e2333f, the internal structire was totally different and
// not supported by this.
type vmElfDbg struct {
	ef        *elf.File
	longSize  uint64 // 4 for 32bit kernel, 8 for 64bit kernel
	desc      elf.Symbol
	descSize  uint64 // sizeof(struct prb_desc)
	startOff  uint64 // offsetof(struct prb_desc, text_blk_lpos.begin)
	info      elf.Symbol
	infoSize  uint64 // sizeof(struct printk_info)
	txtLenOff uint64 // offsetof(struct printk_info, text_len)
	log       uint64 // log_buf
	logLen    uint64 // log_buf_len
}

func (inst *instance) elfOpen(vmlinux string) (vmElfDbg, error) {
	var ed vmElfDbg

	ef, err := elf.Open(vmlinux)
	if err != nil {
		return ed, err
	}

	var ss []elf.Symbol
	logshift := 0
	ss, err = ef.Symbols()
	if err != nil {
		return ed, err
	}
	for _, s := range ss {
		if s.Name == "log_buf" {
			log, err := inst.readSym(ef, s)
			if err != nil {
				return ed, err
			}
			ed.log = log
		}
		if s.Name == "log_buf_len" {
			logLen, err := inst.readSym(ef, s)
			if err != nil {
				return ed, err
			}
			ed.logLen = logLen
			logshift = bits.TrailingZeros64(ed.logLen)
		}
		if s.Name == "_printk_rb_static_descs" {
			ed.desc = s
		}
		if s.Name == "_printk_rb_static_infos" {
			ed.info = s
		}
	}

	if logshift == 0 || ed.desc.Value == uint64(0) {
		return ed, fmt.Errorf(
			"could not find log_buf or _printk_rb_static_descs\nlog=%x loglen=%x\n%+v\n%+v\nlogshift=%d",
			ed.log, ed.logLen, ed.desc, ed.info, logshift)
	}

	if ef.FileHeader.Class == elf.ELFCLASS64 {
		ed.longSize = uint64(8)
	} else {
		ed.longSize = uint64(4)
	}
	ed.descSize = ed.desc.Size >> (logshift - 5)
	ed.infoSize = ed.info.Size >> (logshift - 5)
	ed.startOff = ed.longSize
	ed.txtLenOff = ed.longSize * 2

	// These are defined in the kernel:
	// #define PRB_AVGBITS 5
	// #define PRINTK_INFO_SUBSYSTEM_LEN       16
	// #define PRINTK_INFO_DEVICE_LEN          48
	if ed.descSize != 3*ed.longSize ||
		ed.infoSize != 3*ed.longSize+16+48 {
		return ed, fmt.Errorf("unfamiliar format:\nlog=+v\nloglen=+v\ndesc=%+v\ninfo=%+v\nelf=%+v", ed.log, ed.logLen, ed.desc, ed.info, ef)
	}

	ed.ef = ef // keeps @ef open until we explicitly close it

	return ed, nil
}

func (inst *instance) readmem(addr, size uint64) ([]byte, error) {
	// gdb's dump format:
	// (qemu) x/8b 0xc0000000031e3480
	// c0000000031e3480: 0x00 0xe0 0xff 0xff 0x00 0x00 0x00 0x00
	chunk := uint64(2048) // less than 256 is drastically slow
	if size < chunk {
		chunk = size
	}

	ret := make([]byte, 0)
	cpu := 0

	for off := uint64(0); off < size; off += chunk {
		//tmp, err := inst.hmp(fmt.Sprintf("x/%db 0x%x", chunk, addr+off), 0)
		toread := chunk
		if size - off < toread {
			toread = size - off
		}

		tmp, err := inst.hmp(fmt.Sprintf("x/%db 0x%x", toread, addr+off), cpu)
		if err != nil {
			// FIXME
			// Dumping of virtual addresses may fail if MMU is off, try
			// the next CPU where it may be ON
			cpu++
			tmp, err = inst.hmp(fmt.Sprintf("x/%db 0x%x", toread, addr+off), cpu)
		}
		if err != nil {
			return nil, fmt.Errorf("readmem(%x, %x) -> %v", addr, size, err)
		}
		for _, c := range strings.Split(tmp, "\n") {
			if c == "" {
				continue
			}
			for i, c2 := range strings.Fields(c) {
				var b byte
				if i == 0 {
					continue
				}
				if _, err = fmt.Sscanf(c2, "0x%x", &b); err != nil {
					return nil, fmt.Errorf("readmem scanf(%v) -> %v\ntmp=%v\ncpu=%d", c2, err, tmp, cpu)
				}
				ret = append(ret, b)//[n] = b
			}
		}
	}
	return ret, nil
}

func (inst *instance) decodeInt(ef *elf.File, a []byte, size uint64) (uint64, error) {
	switch size {
	case 2:
		return uint64(ef.ByteOrder.Uint16(a)), nil
	case 4:
		return uint64(ef.ByteOrder.Uint32(a)), nil
	case 8:
		return ef.ByteOrder.Uint64(a), nil
	default:
		return uint64(0xffffffffffffffff), fmt.Errorf(`unsuppported size: %v`, size)
	}
}

func (inst *instance) readSym(ef *elf.File, s elf.Symbol) (uint64, error) {
	tmp, err := inst.readmem(s.Value, s.Size)
	if err != nil {
		return 0, err
	}
	return inst.decodeInt(ef, tmp, s.Size)
}

func (inst *instance) readVal(ef *elf.File, a []byte, start, size uint64) (uint64, error) {
	return inst.decodeInt(ef, a[start:start+size], size)
}

func (inst *instance) dumpPrintk() ([]byte, error) {
	// Try explicit image first.
	ed, err := inst.elfOpen(inst.cfg.Kernel)
	if err != nil {
		// Quite possible the image was zImage, try one from kernel_obj.
		ed, err = inst.elfOpen(inst.kernelObj + "/vmlinux")
	}
	if err != nil {
		return nil, err
	}
	defer ed.ef.Close()

	var descarr, infoarr, ret []byte

	ret = append(ret, []byte(fmt.Sprintf("dumpPrintk\n%+v\n%+v\n", ed.desc, ed.info))...)
	descarr, err = inst.readmem(ed.desc.Value, ed.desc.Size)
	if err != nil {
		return nil, err
	}
	infoarr, err = inst.readmem(ed.info.Value, ed.info.Size)
	if err != nil {
		return nil, err
	}

	for i := uint64(0); i < ed.desc.Size/ed.descSize; i++ {
		id, _ := inst.readVal(ed.ef, descarr, i*ed.descSize, ed.longSize)
		start, _ := inst.readVal(ed.ef, descarr, i*ed.descSize+ed.startOff, ed.longSize)
		start &= ed.logLen - 1
		start += ed.longSize // skip the ID

//
//#define DESC_SV_BITS            (sizeof(unsigned long) * 8)
//#define DESC_FLAGS_SHIFT        (DESC_SV_BITS - 2)
//#define DESC_FLAGS_MASK         (3UL << DESC_FLAGS_SHIFT)
//#define DESC_STATE(sv)          (3UL & (sv >> DESC_FLAGS_SHIFT))
//desc_committed  = 0x1,  /* committed by writer, could get reopened */    
//desc_finalized  = 0x2,  /* committed, no further modification allowed */ 

		state := id >> (ed.longSize * 8 - 2)

		if state != 1 && state != 2 {
			continue
		}

		txtlen, _ := inst.readVal(ed.ef, infoarr, i*ed.infoSize+ed.txtLenOff, 2)
		if msg, err := inst.readmem(ed.log+start, txtlen); err != nil {
			return ret, err
		} else if id != 0 {
			ret = append(ret, []byte(fmt.Sprintf("%x %v\n", id, string(msg)))...)
		}
	}

	return ret, nil
}
