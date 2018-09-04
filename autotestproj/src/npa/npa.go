package npa

/*
#cgo CFLAGS: -I. -I/home/ych/zr9101/install/npa/lib/include/
#cgo LDFLAGS:-L/home/ych/zr9101/install/npa/lib/ -lstdc++ -lc -lpthread -ldl -lnpa
#include "platform.h"
#include "NpaLib.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "common.h"
*/
import "C"

import (
	"fmt"
)

type DedupCfg struct {
	portid    uint16
	dedupflag uint64
	timeout   uint64
}

type Npastat struct {
	AllPackets         uint64
	AllBytes           uint64
	ArpPackets         uint64
	ArpBytes           uint64
	IpPackets          uint64
	IpBytes            uint64
	VlanPackets        uint64
	VlanBytes          uint64
	MplsPackets        uint64
	MplsBytes          uint64
	UniCastPackets     uint64
	UniCastBytes       uint64
	BroadCastPackets   uint64
	BroadCastBytes     uint64
	MultiCastPackets   uint64
	MultiCastBytes     uint64
	UdpPackets         uint64
	UdpBytes           uint64
	TcpPackets         uint64
	TcpBytes           uint64
	IcmpPackets        uint64
	IcmpBytes          uint64
	Packet64s          uint64
	Packet65To127s     uint64
	Packet128To255s    uint64
	Packet256To511s    uint64
	Packet512To1023s   uint64
	Packet1024To1518s  uint64
	UnderSizePackets   uint64
	OverSizePackets    uint64
	FragmentPackets    uint64
	CollisionPackets   uint64
	DropPackets        uint64
	CrcAlignErrPackets uint64
	JabberPackets      uint64
	DedupDropPackets   uint64
	AclDropPackets     uint64
}

type MacCfg struct {
	srcmac     [6]uint8
	dstmac     [6]uint8
	srcmacflag uint8
	dstmacflag uint8
}

func Npa_setdedup(cfg DedupCfg) (ret int) {
	var ret_c C.int

	ret_c = C.NpaSetDedup((C.ushort)(cfg.portid), (C.ulong)(cfg.dedupflag), (C.ulong)(cfg.timeout))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	fmt.Printf("Npa_setdedup portid:%d, dedupflag:0x%x, timeout:%d ret:%d \n", cfg.portid, cfg.dedupflag, cfg.timeout, ret)

	return ret
}
func Npa_getdedup(portid uint16) (ret int, cfg DedupCfg) {
	var ret_c C.int

	cfg.portid = portid

	ret_c = C.NpaGetDedup((C.ushort)(cfg.portid), (*C.ulong)(&cfg.dedupflag), (*C.ulong)(&cfg.timeout))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	fmt.Printf("Npa_getdedup portid:%d, dedupflag:0x%x, timeout:%d, ret:%d \n", cfg.portid, cfg.dedupflag, cfg.timeout, ret)

	return ret, cfg
}
func Npa_clrdedup(portid uint16) (ret int) {
	var ret_c C.int

	ret_c = C.NpaClrDedup((C.ushort)(portid))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	fmt.Printf("Npa_clrdedup portid:%d, ret:%d \n", portid, ret)

	return ret
}
func Npa_getstat(portid uint16) (ret int, stat Npastat) {
	var ret_c C.int
	var stat_c C.ST_NPA_STAT

	ret_c = C.NpaGetStat((C.ushort)(portid), (&stat_c))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}
	stat.AllPackets = (uint64)(stat_c.ulAllPackets)
	stat.AllBytes = (uint64)(stat_c.ulAllBytes)
	stat.ArpPackets = (uint64)(stat_c.ulArpPackets)
	stat.ArpBytes = (uint64)(stat_c.ulArpBytes)
	stat.IpPackets = (uint64)(stat_c.ulIpPackets)
	stat.IpBytes = (uint64)(stat_c.ulIpBytes)
	stat.VlanPackets = (uint64)(stat_c.ulVlanPackets)
	stat.VlanBytes = (uint64)(stat_c.ulVlanBytes)
	stat.MplsPackets = (uint64)(stat_c.ulMplsPackets)
	stat.MplsBytes = (uint64)(stat_c.ulMplsBytes)
	stat.UniCastPackets = (uint64)(stat_c.ulUniCastPackets)
	stat.UniCastBytes = (uint64)(stat_c.ulUniCastBytes)
	stat.BroadCastPackets = (uint64)(stat_c.ulBroadCastPackets)
	stat.BroadCastBytes = (uint64)(stat_c.ulBroadCastBytes)
	stat.MultiCastPackets = (uint64)(stat_c.ulMultiCastPackets)
	stat.MultiCastBytes = (uint64)(stat_c.ulMultiCastBytes)
	stat.UdpPackets = (uint64)(stat_c.ulUdpPackets)
	stat.UdpBytes = (uint64)(stat_c.ulUdpBytes)
	stat.TcpPackets = (uint64)(stat_c.ulTcpPackets)
	stat.TcpBytes = (uint64)(stat_c.ulTcpBytes)
	stat.IcmpPackets = (uint64)(stat_c.ulIcmpPackets)
	stat.IcmpBytes = (uint64)(stat_c.ulIcmpBytes)
	stat.Packet64s = (uint64)(stat_c.ul64Packets)
	stat.Packet65To127s = (uint64)(stat_c.ul65To127Packets)
	stat.Packet128To255s = (uint64)(stat_c.ul128To255Packets)
	stat.Packet256To511s = (uint64)(stat_c.ul256To511Packets)
	stat.Packet512To1023s = (uint64)(stat_c.ul512To1023Packets)
	stat.Packet1024To1518s = (uint64)(stat_c.ul1024To1518Packets)
	stat.UnderSizePackets = (uint64)(stat_c.ulUnderSizePackets)
	stat.OverSizePackets = (uint64)(stat_c.ulOverSizePackets)
	stat.FragmentPackets = (uint64)(stat_c.ulFragmentPackets)
	stat.CollisionPackets = (uint64)(stat_c.ulCollisionPackets)
	stat.DropPackets = (uint64)(stat_c.ulDropPackets)
	stat.CrcAlignErrPackets = (uint64)(stat_c.ulCrcAlignErrPackets)
	stat.JabberPackets = (uint64)(stat_c.ulJabberPackets)
	stat.DedupDropPackets = (uint64)(stat_c.ulDedupDropPackets)
	stat.AclDropPackets = (uint64)(stat_c.ulAclDropPackets)

	fmt.Println("AllPackets        :", stat.AllPackets)
	fmt.Println("AllBytes          :", stat.AllBytes)
	fmt.Println("ArpPackets        :", stat.ArpPackets)
	fmt.Println("ArpBytes          :", stat.ArpBytes)
	fmt.Println("IpPackets         :", stat.IpPackets)
	fmt.Println("IpBytes           :", stat.IpBytes)
	fmt.Println("VlanPackets       :", stat.VlanPackets)
	fmt.Println("VlanBytes         :", stat.VlanBytes)
	fmt.Println("MplsPackets       :", stat.MplsPackets)
	fmt.Println("MplsBytes         :", stat.MplsBytes)
	fmt.Println("UniCastPackets    :", stat.UniCastPackets)
	fmt.Println("UniCastBytes      :", stat.UniCastBytes)
	fmt.Println("BroadCastPackets  :", stat.BroadCastPackets)
	fmt.Println("BroadCastBytes    :", stat.BroadCastBytes)
	fmt.Println("MultiCastPackets  :", stat.MultiCastPackets)
	fmt.Println("MultiCastBytes    :", stat.MultiCastBytes)
	fmt.Println("UdpPackets        :", stat.UdpPackets)
	fmt.Println("UdpBytes          :", stat.UdpBytes)
	fmt.Println("TcpPackets        :", stat.TcpPackets)
	fmt.Println("TcpBytes          :", stat.TcpBytes)
	fmt.Println("IcmpPackets       :", stat.IcmpPackets)
	fmt.Println("IcmpBytes         :", stat.IcmpBytes)
	fmt.Println("Packet64s         :", stat.Packet64s)
	fmt.Println("Packet65To127s    :", stat.Packet65To127s)
	fmt.Println("Packet128To255s   :", stat.Packet128To255s)
	fmt.Println("Packet256To511s   :", stat.Packet256To511s)
	fmt.Println("Packet512To1023s  :", stat.Packet512To1023s)
	fmt.Println("Packet1024To1518s :", stat.Packet1024To1518s)
	fmt.Println("UnderSizePackets  :", stat.UnderSizePackets)
	fmt.Println("OverSizePackets   :", stat.OverSizePackets)
	fmt.Println("FragmentPackets   :", stat.FragmentPackets)
	fmt.Println("CollisionPackets  :", stat.CollisionPackets)
	fmt.Println("DropPackets       :", stat.DropPackets)
	fmt.Println("CrcAlignErrPackets:", stat.CrcAlignErrPackets)
	fmt.Println("JabberPackets     :", stat.JabberPackets)
	fmt.Println("DedupDropPackets  :", stat.DedupDropPackets)
	fmt.Println("AclDropPackets    :", stat.AclDropPackets)

	return ret, stat
}
func Npa_clrstat(portid uint16) (ret int) {
	var ret_c C.int

	ret_c = C.NpaClrStat((C.ushort)(portid))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	fmt.Printf("Npa_clrstat portid:%d, ret:%d \n", portid, ret)

	return ret
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

		fmt.Printf("Npa_setdedup portid:%d, src mac:%02X:%02X:%02X:%02X:%02X:%02X ret:%d \n",
			portid, cfg.srcmac[0], cfg.srcmac[1], cfg.srcmac[2], cfg.srcmac[3], cfg.srcmac[4], cfg.srcmac[5], ret)
	}

	if cfg.dstmacflag == 1 {
		ret_c = C.NpaSetMacEntry((C.ushort)(portid), (C.uchar)(0), (*C.uchar)(&cfg.dstmac[0]))
		if ret_c != 0 {
			ret = -1
		} else {
			ret = 0
		}

		fmt.Printf("Npa_setdedup portid:%d, dst mac:%02X:%02X:%02X:%02X:%02X:%02X ret:%d \n",
			portid, cfg.dstmac[0], cfg.dstmac[1], cfg.dstmac[2], cfg.dstmac[3], cfg.dstmac[4], cfg.dstmac[5], ret)
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

	fmt.Println("portid     :", portid)
	fmt.Println("srcmac :", macentry.srcmac)
	fmt.Println("dstmac :", macentry.dstmac)

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

	fmt.Printf("Npa_clrmacentry portid:%d, ret:%d \n", portid, ret)

	return ret
}

func Npa_init() int {
	var ret_c C.int
	var decfg DedupCfg
	var macentry MacCfg

	ret_c = C.Cm_NicIsOnLine()
	if ret_c != 1 {
		fmt.Println("Nic Is Off Line:", ret_c)
		return -1
	}

	ret_c = C.NpaInit()
	if ret_c != 0 {
		fmt.Println("NpaInit fail")
		return -1
	}
	decfg.portid = 1
	decfg.dedupflag = 0xff
	decfg.timeout = 10

	Npa_setdedup(decfg)
	_, decfg = Npa_getdedup(decfg.portid)
	Npa_clrdedup(decfg.portid)
	_, decfg = Npa_getdedup(decfg.portid)

	_, _ = Npa_getstat(0)
	//	_ = Npa_clrstat(0)
	//	_, _ = Npa_getstat(0)

	_, macentry = Npa_getmacentry(0)
	macentry.srcmacflag = 1
	macentry.srcmac[0] = 0x01
	macentry.srcmac[1] = 0x02
	macentry.srcmac[2] = 0x03
	macentry.srcmac[3] = 0x04
	macentry.srcmac[4] = 0x05
	macentry.srcmac[5] = 0x06
	macentry.dstmacflag = 1
	macentry.dstmac[0] = 0x11
	macentry.dstmac[1] = 0x12
	macentry.dstmac[2] = 0x13
	macentry.dstmac[3] = 0x14
	macentry.dstmac[4] = 0x15
	macentry.dstmac[5] = 0x16
	_ = Npa_setmacentry(0, macentry)
	_, macentry = Npa_getmacentry(0)
	_ = Npa_clrmacentry(0)
	_, macentry = Npa_getmacentry(0)
	return 0
}

func Npa_exit() {
	fmt.Printf("Npa_exit\n")
	C.NpaExit()
}
