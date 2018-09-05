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

type MacCfg struct {
	srcmac     [6]uint8
	dstmac     [6]uint8
	srcmacflag uint8
	dstmacflag uint8
}

func Npa_setmacentry(portid uint16, cfg MacCfg) (ret int) {
	var ret_c C.int

	if cfg.srcmacflag == 1 {
		ret_c = C.NpaSetMacEntry((C.ushort)(portid), (C.uchar)(1), (*C.uchar)(&cfg.srcmac[0]))
		if ret_c != 0 {
			ret = -1
		} else {
			ret = 0
		}
	}

	if cfg.dstmacflag == 1 {
		ret_c = C.NpaSetMacEntry((C.ushort)(portid), (C.uchar)(0), (*C.uchar)(&cfg.dstmac[0]))
		if ret_c != 0 {
			ret = -1
		} else {
			ret = 0
		}
	}

	return ret
}

func Npa_getmacentry(portid uint16) (ret int, macentry MacCfg) {
	var ret_c C.int

	ret_c = C.NpaGetMacEntry((C.ushort)(portid), (*C.uchar)(&macentry.srcmac[0]), (*C.uchar)(&macentry.dstmac[0]))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	return ret, macentry
}

func Npa_clrmacentry(portid uint16) (ret int) {
	var ret_c C.int

	ret_c = C.NpaClrMacEntry((C.ushort)(portid))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	return ret
}
