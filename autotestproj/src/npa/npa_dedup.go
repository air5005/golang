package npa

/*
#cgo CFLAGS: -I. -I/home/ych/zr9101/install/npa/lib/include/
#cgo LDFLAGS:-L/home/ych/zr9101/install/npa/lib/ -lstdc++ -lc -lpthread -ldl -lnpa
#include "platform.h"
#include "platform_typedef.h"
#include "NpaLib.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "common.h"
#include "PLog.h"
#include "SncpServer.h"
*/
import "C"

type DedupCfg struct {
	dedupflag uint64
	timeout   uint64
}

const (
	Dedup_ignore_mac     = 0x0001
	Dedup_ignore_ttl     = 0x0002
	Dedup_ignore_srcip   = 0x0004
	Dedup_ignore_dstip   = 0x0008
	Dedup_ignore_proto   = 0x0010
	Dedup_ignore_srcport = 0x0020
	Dedup_ignore_dstport = 0x0040
	Dedup_ignore_vxlan   = 0x0080
)

func Npa_setdedup(cardid uint16, portid uint16, cfg DedupCfg) (ret int) {
	var ret_c C.int

	ret_c = C.NpaSetDedup((C.ushort)(cardid), (C.ushort)(portid), (C.ulong)(cfg.dedupflag), (C.ulong)(cfg.timeout))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	return ret
}

func Npa_getdedup(cardid uint16, portid uint16) (ret int, cfg DedupCfg) {
	var ret_c C.int

	ret_c = C.NpaGetDedup((C.ushort)(cardid), (C.ushort)(portid), (*C.ulong)(&cfg.dedupflag), (*C.ulong)(&cfg.timeout))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	return ret, cfg
}

func Npa_clrdedup(cardid uint16, portid uint16) (ret int) {
	var ret_c C.int

	ret_c = C.NpaClrDedup((C.ushort)(cardid), (C.ushort)(portid))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	return ret
}
