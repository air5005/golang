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

import (
	"common"
	"fmt"
	"unsafe"
)

type DedupCfg struct {
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
	ModSrcMacPackets   uint64
	ModDstMacPackets   uint64
}

type MacCfg struct {
	srcmac     [6]uint8
	dstmac     [6]uint8
	srcmacflag uint8
	dstmacflag uint8
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

const Npa_max_port_num = 2

const (
	Npa_test_acl = iota
	Npa_test_dedup_no_ignore
	Npa_test_dedup_ignore_mac
	Npa_test_dedup_ignore_ttl
	Npa_test_dedup_ignore_srcip
	Npa_test_dedup_ignore_dstip
	Npa_test_dedup_ignore_srcport
	Npa_test_dedup_ignore_dstport
	Npa_test_dedup_ignore_vxlan
	Npa_test_mac_modifed
)

var testpcap = [Npa_test_mac_modifed + 1]string{
	"acl_test_pkt.pcap",
	"dedup_test_pkt_org.pcap",
	"dedup_test_pkt_diff_mac.pcap",
	"dedup_test_pkt_diff_ttl.pcap",
	"dedup_test_pkt_diff_src_ip.pcap",
	"dedup_test_pkt_diff_dst_ip.pcap",
	"dedup_test_pkt_diff_src_port.pcap",
	"dedup_test_pkt_diff_dst_port.pcap",
	"dedup_test_pkt_diff_vxlan.pcap",
	"dedup_test_pkt_org.pcap",
}

var (
	npa_iface    string
	npa_pcappath string
	npa_fast     bool
)

func Npa_setdedup(portid uint16, cfg DedupCfg) (ret int) {
	var ret_c C.int

	ret_c = C.NpaSetDedup((C.ushort)(portid), (C.ulong)(cfg.dedupflag), (C.ulong)(cfg.timeout))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	//	fmt.Printf("Npa_setdedup portid:%d, dedupflag:0x%x, timeout:%d ret:%d \n", portid, cfg.dedupflag, cfg.timeout, ret)

	return ret
}
func Npa_getdedup(portid uint16) (ret int, cfg DedupCfg) {
	var ret_c C.int

	ret_c = C.NpaGetDedup((C.ushort)(portid), (*C.ulong)(&cfg.dedupflag), (*C.ulong)(&cfg.timeout))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	//	fmt.Printf("Npa_getdedup portid:%d, dedupflag:0x%x, timeout:%d, ret:%d \n", portid, cfg.dedupflag, cfg.timeout, ret)

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

	//	fmt.Printf("Npa_clrdedup portid:%d, ret:%d \n", portid, ret)

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
	stat.ModSrcMacPackets = (uint64)(stat_c.ulModifedSrcMacPackets)
	stat.ModDstMacPackets = (uint64)(stat_c.ulModifedDstMacPackets)

	//	fmt.Println("AllPackets        :", stat.AllPackets)
	//	fmt.Println("AllBytes          :", stat.AllBytes)
	//	fmt.Println("ArpPackets        :", stat.ArpPackets)
	//	fmt.Println("ArpBytes          :", stat.ArpBytes)
	//	fmt.Println("IpPackets         :", stat.IpPackets)
	//	fmt.Println("IpBytes           :", stat.IpBytes)
	//	fmt.Println("VlanPackets       :", stat.VlanPackets)
	//	fmt.Println("VlanBytes         :", stat.VlanBytes)
	//	fmt.Println("MplsPackets       :", stat.MplsPackets)
	//	fmt.Println("MplsBytes         :", stat.MplsBytes)
	//	fmt.Println("UniCastPackets    :", stat.UniCastPackets)
	//	fmt.Println("UniCastBytes      :", stat.UniCastBytes)
	//	fmt.Println("BroadCastPackets  :", stat.BroadCastPackets)
	//	fmt.Println("BroadCastBytes    :", stat.BroadCastBytes)
	//	fmt.Println("MultiCastPackets  :", stat.MultiCastPackets)
	//	fmt.Println("MultiCastBytes    :", stat.MultiCastBytes)
	//	fmt.Println("UdpPackets        :", stat.UdpPackets)
	//	fmt.Println("UdpBytes          :", stat.UdpBytes)
	//	fmt.Println("TcpPackets        :", stat.TcpPackets)
	//	fmt.Println("TcpBytes          :", stat.TcpBytes)
	//	fmt.Println("IcmpPackets       :", stat.IcmpPackets)
	//	fmt.Println("IcmpBytes         :", stat.IcmpBytes)
	//	fmt.Println("Packet64s         :", stat.Packet64s)
	//	fmt.Println("Packet65To127s    :", stat.Packet65To127s)
	//	fmt.Println("Packet128To255s   :", stat.Packet128To255s)
	//	fmt.Println("Packet256To511s   :", stat.Packet256To511s)
	//	fmt.Println("Packet512To1023s  :", stat.Packet512To1023s)
	//	fmt.Println("Packet1024To1518s :", stat.Packet1024To1518s)
	//	fmt.Println("UnderSizePackets  :", stat.UnderSizePackets)
	//	fmt.Println("OverSizePackets   :", stat.OverSizePackets)
	//	fmt.Println("FragmentPackets   :", stat.FragmentPackets)
	//	fmt.Println("CollisionPackets  :", stat.CollisionPackets)
	//	fmt.Println("DropPackets       :", stat.DropPackets)
	//	fmt.Println("CrcAlignErrPackets:", stat.CrcAlignErrPackets)
	//	fmt.Println("JabberPackets     :", stat.JabberPackets)
	//	fmt.Println("DedupDropPackets  :", stat.DedupDropPackets)
	//	fmt.Println("AclDropPackets    :", stat.AclDropPackets)
	//	fmt.Println("ModSrcMacPackets  :", stat.ModSrcMacPackets)
	//	fmt.Println("ModDstMacPackets  :", stat.ModDstMacPackets)

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

	//	fmt.Printf("Npa_clrstat portid:%d, ret:%d \n", portid, ret)

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

		//		fmt.Printf("Npa_setdedup portid:%d, src mac:%02X:%02X:%02X:%02X:%02X:%02X ret:%d \n",
		//			portid, cfg.srcmac[0], cfg.srcmac[1], cfg.srcmac[2], cfg.srcmac[3], cfg.srcmac[4], cfg.srcmac[5], ret)
	}

	if cfg.dstmacflag == 1 {
		ret_c = C.NpaSetMacEntry((C.ushort)(portid), (C.uchar)(0), (*C.uchar)(&cfg.dstmac[0]))
		if ret_c != 0 {
			ret = -1
		} else {
			ret = 0
		}

		//		fmt.Printf("Npa_setdedup portid:%d, dst mac:%02X:%02X:%02X:%02X:%02X:%02X ret:%d \n",
		//			portid, cfg.dstmac[0], cfg.dstmac[1], cfg.dstmac[2], cfg.dstmac[3], cfg.dstmac[4], cfg.dstmac[5], ret)
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

	//	fmt.Println("portid :", portid)
	//	fmt.Println("srcmac :", macentry.srcmac)
	//	fmt.Println("dstmac :", macentry.dstmac)

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

	//	fmt.Printf("Npa_clrmacentry portid:%d, ret:%d \n", portid, ret)

	return ret
}

func Npa_TestConfig() int {
	var decfg DedupCfg
	var macentry MacCfg
	var portid uint16

	for portid = 0; portid < Npa_max_port_num; portid++ {
		//test dedup config
		decfg.dedupflag = Dedup_ignore_mac | Dedup_ignore_ttl | Dedup_ignore_srcip | Dedup_ignore_dstip | Dedup_ignore_proto | Dedup_ignore_srcport | Dedup_ignore_dstport | Dedup_ignore_vxlan
		decfg.timeout = 100

		ret := Npa_setdedup(portid, decfg)
		if ret != 0 {
			fmt.Printf("Npa Dedup Test: set dedup cfg Fail \n")
			return ret
		}

		ret, respdecfg := Npa_getdedup(portid)
		if ret != 0 {
			fmt.Printf("Npa Dedup Test: get dedup cfg Fail \n")
			return ret
		}

		if decfg.dedupflag != respdecfg.dedupflag || decfg.timeout != respdecfg.timeout {
			fmt.Printf("Npa Dedup Test: get dedup cfg data Fail \n")
			return ret
		}

		ret = Npa_clrdedup(portid)
		if ret != 0 {
			fmt.Printf("Npa Dedup Test: clr dedup cfg Fail \n")
			return ret
		}

		ret, respdecfg = Npa_getdedup(portid)
		if respdecfg.dedupflag != 0 || respdecfg.timeout != 0 {
			fmt.Printf("Npa Dedup Test: clr dedup cfg data Fail \n")
			return ret
		}
	}

	fmt.Println("Npa Dedup Test Success")

	//test modifed mac config
	for portid = 0; portid < Npa_max_port_num; portid++ {
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
		ret := Npa_setmacentry(portid, macentry)
		if ret != 0 {
			fmt.Printf("Npa modifed mac Test: set dedup cfg Fail \n")
			return ret
		}

		ret, respmacentry := Npa_getmacentry(portid)
		if ret != 0 {
			fmt.Printf("Npa modifed mac Test: get dedup cfg Fail \n")
			return ret
		}

		for index, value := range respmacentry.srcmac {
			if macentry.srcmac[index] != value {
				fmt.Printf("Npa modifed mac Test: get dedup cfg data Fail \n")
				fmt.Println("set src mac :", macentry.srcmac)
				fmt.Println("resp src mac :", respmacentry.srcmac)
				return -1
			}
		}
		for index, value := range respmacentry.dstmac {
			if macentry.dstmac[index] != value {
				fmt.Printf("Npa modifed mac Test: get dedup cfg data Fail \n")
				fmt.Println("set dst mac :", macentry.dstmac)
				fmt.Println("resp dst mac :", respmacentry.dstmac)
				return -1
			}
		}

		ret = Npa_clrmacentry(portid)
		if ret != 0 {
			fmt.Printf("Npa modifed mac Test: clr dedup cfg Fail \n")
			return ret
		}

		ret, respmacentry = Npa_getmacentry(portid)
		if ret != 0 {
			fmt.Printf("Npa modifed mac Test: get dedup cfg Fail \n")
			return ret
		}

		for _, value := range respmacentry.srcmac {
			if 0 != value {
				fmt.Printf("Npa modifed mac Test: get dedup cfg data Fail \n")
				fmt.Println("resp src mac :", respmacentry.srcmac)
				return -1
			}
		}
		for _, value := range respmacentry.dstmac {
			if 0 != value {
				fmt.Printf("Npa modifed mac Test: get dedup cfg data Fail \n")
				fmt.Println("resp dst mac :", respmacentry.dstmac)
				return -1
			}
		}
	}

	fmt.Println("Npa modifed mac Test Success")

	return 0
}

func Npa_InitCli() int {
	var ret_c C.int

	ret_c = C.NpaSncpServerInit()
	if ret_c != 0 {
		fmt.Println("NpaSncpServerInit fail")
		return -1
	} else {
		fmt.Println("NpaSncpServerInit success")
	}

	go C.SncpProcessCmdSerial((unsafe.Pointer)(nil))

	return 0
}

func Npa_TestPacket() int {

	for index := Npa_test_acl; index <= Npa_test_mac_modifed; index++ {
		switch index {
		case Npa_test_acl:
		case Npa_test_dedup_no_ignore:
		case Npa_test_dedup_ignore_mac:
		case Npa_test_dedup_ignore_ttl:
		case Npa_test_dedup_ignore_srcip:
		case Npa_test_dedup_ignore_dstip:
		case Npa_test_dedup_ignore_srcport:
		case Npa_test_dedup_ignore_dstport:
		case Npa_test_dedup_ignore_vxlan:
		case Npa_test_mac_modifed:
			common.Com_sendpcap(npa_iface, npa_pcappath+testpcap[index], npa_fast)
		default:
			fmt.Println("err para, index:", index)
		}
	}

	return 0
}

func Npa_init(iface string, pcappath string, fast bool) int {
	var ret_c C.int

	fmt.Println(iface, pcappath, fast)

	npa_iface = iface
	npa_pcappath = pcappath
	npa_fast = fast

	//	for index := Npa_test_acl; index <= Npa_test_mac_modifed; index++ {
	//		fmt.Println(index, npa_pcappath+testpcap[index])
	//	}

	ret_c = C.Cm_NicIsOnLine()
	if ret_c != 1 {
		fmt.Println("Nic Is Off Line:", ret_c)
		return -1
	}

	ret_c = C.NpaInit()
	if ret_c != 0 {
		fmt.Println("NpaInit fail")
		return -1
	} else {
		fmt.Println("NpaInit success")
	}

	ret_c = C.Plog_SetLog(0, 0xff, 1)
	ret_c |= C.Plog_SetLog(1, 0xff, 1)
	if ret_c != 0 {
		fmt.Println("Plog_SetLog fail")
		return -1
	} else {
		fmt.Println("Plog_SetLog success")
	}

	//	ret := Npa_InitCli()
	//	if ret != 0 {
	//		fmt.Println("Npa_InitCli fail")
	//		return -1
	//	} else {
	//		fmt.Println("Npa_InitCli success")
	//	}

	return 0
}

func Npa_exit() {
	fmt.Printf("Npa_exit\n")
	C.NpaExit()
}
