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

const Npa_max_port_num = 2

const (
	NPA_TEST_ACL = iota
	NPA_TEST_DEDUP_NO_IGNORE
	NPA_TEST_DEDUP_IGNORE_MAC
	NPA_TEST_DEDUP_IGNORE_TTL
	NPA_TEST_DEDUP_IGNORE_SRCIP
	NPA_TEST_DEDUP_IGNORE_DSTIP
	NPA_TEST_DEDUP_IGNORE_SRCPORT
	NPA_TEST_DEDUP_IGNORE_DSTPORT
	NPA_TEST_DEDUP_IGNORE_VXLAN
	NPA_TEST_MAC_MODIFED
)

var testpcap = [NPA_TEST_MAC_MODIFED + 1]string{
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

	fmt.Println("Npa Dedup config Test Success")

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

	fmt.Println("Npa modifed mac config Test Success")

	//test modifed acl config
	for portid = 0; portid < Npa_max_port_num; portid++ {
		var cfg AclCfg

		cfg.SrcIp = 0x01010101
		cfg.SrcIpMask = 0xffffff00
		cfg.DstIp = 0x02020202
		cfg.DstIpMask = 0xffffff00
		cfg.SrcPortMin = 1
		cfg.SrcPortMax = 65535
		cfg.DstPortMin = 1
		cfg.DstPortMax = 65535
		cfg.Index = 0
		cfg.Protocol = 17
		cfg.ActionType = ACL_ACTION_DROP
		cfg.PortId = portid

		ret := Npa_addacl(cfg)
		if ret != 0 {
			fmt.Printf("Npa_add acl fail \n")
			return -1
		}

		ret, respcfg := Npa_getacl(cfg.PortId, cfg.Index)
		if ret != 0 {
			fmt.Printf("Npa_getacl fail \n")
			return -1
		}

		if cfg.SrcIp != respcfg.SrcIp ||
			cfg.SrcIpMask != respcfg.SrcIpMask ||
			cfg.DstIp != respcfg.DstIp ||
			cfg.DstIpMask != respcfg.DstIpMask ||
			cfg.SrcPortMin != respcfg.SrcPortMin ||
			cfg.SrcPortMax != respcfg.SrcPortMax ||
			cfg.DstPortMin != respcfg.DstPortMin ||
			cfg.DstPortMax != respcfg.DstPortMax ||
			cfg.Index != respcfg.Index ||
			cfg.Protocol != respcfg.Protocol ||
			cfg.ActionType != respcfg.ActionType ||
			cfg.PortId != respcfg.PortId {
			fmt.Printf("Npa_getacl data fail \n")
			return -1
		}

		cfg.SrcIp = 0x0a0a0a0a
		cfg.SrcIpMask = 0xffffffff
		cfg.DstIp = 0x0b0b0b0b
		cfg.DstIpMask = 0xffffffff
		cfg.SrcPortMin = 10000
		cfg.SrcPortMax = 20000
		cfg.DstPortMin = 10000
		cfg.DstPortMax = 20000
		cfg.Index = 0
		cfg.Protocol = 18
		cfg.ActionType = ACL_ACTION_FW
		cfg.PortId = portid

		ret = Npa_modacl(cfg)
		if ret != 0 {
			fmt.Printf("Npa_modacl fail \n")
			return -1
		}

		ret, respcfg = Npa_getacl(cfg.PortId, cfg.Index)
		if ret != 0 {
			fmt.Printf("Npa_getacl fail \n")
			return -1
		}

		if cfg.SrcIp != respcfg.SrcIp ||
			cfg.SrcIpMask != respcfg.SrcIpMask ||
			cfg.DstIp != respcfg.DstIp ||
			cfg.DstIpMask != respcfg.DstIpMask ||
			cfg.SrcPortMin != respcfg.SrcPortMin ||
			cfg.SrcPortMax != respcfg.SrcPortMax ||
			cfg.DstPortMin != respcfg.DstPortMin ||
			cfg.DstPortMax != respcfg.DstPortMax ||
			cfg.Index != respcfg.Index ||
			cfg.Protocol != respcfg.Protocol ||
			cfg.ActionType != respcfg.ActionType ||
			cfg.PortId != respcfg.PortId {
			fmt.Printf("Npa_getacl data fail \n")
			return -1
		}

		ret = Npa_delacl(cfg.PortId, cfg.Index)
		if ret != 0 {
			fmt.Printf("Npa_delacl fail \n")
			return -1
		}

		ret, _ = Npa_getacl(cfg.PortId, cfg.Index)
		if ret == 0 {
			fmt.Printf("Npa_getacl fail \n")
			return -1
		}
	}
	fmt.Println("Npa acl config Test Success")

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

func Npa_CfgDedup(portid uint16, dedupflag uint64, timeout uint64) int {
	var decfg DedupCfg

	if portid >= Npa_max_port_num {
		fmt.Println("Inpara Err, portid:", portid, "dedupflag:", dedupflag)
		return -1
	}
	ret := Npa_clrdedup(portid)
	if ret != 0 {
		fmt.Printf("Npa Dedup Test: clr dedup cfg Fail \n")
		return -1
	}
	decfg.dedupflag = dedupflag
	decfg.timeout = timeout
	ret = Npa_setdedup(portid, decfg)
	if ret != 0 {
		fmt.Printf("Npa Dedup Test: set dedup cfg Fail \n")
		return -1
	}
	ret, respdecfg := Npa_getdedup(portid)
	if ret != 0 {
		fmt.Printf("Npa Dedup Test: get dedup cfg Fail \n")
		return -1
	}

	if decfg.dedupflag != respdecfg.dedupflag || decfg.timeout != respdecfg.timeout {
		fmt.Printf("Npa Dedup Test: get dedup cfg data Fail \n")
		return -1
	}

	return 0
}

func Npa_TestPacketMac(portid uint16, testindex uint64) int {
	var cfg MacCfg

	Npa_clrstat(portid)

	cfg.srcmacflag = 1
	cfg.dstmacflag = 1
	cfg.srcmac[0] = 00
	cfg.srcmac[1] = 11
	cfg.srcmac[2] = 22
	cfg.srcmac[3] = 33
	cfg.srcmac[4] = 44
	cfg.srcmac[5] = 55
	cfg.dstmac[0] = 00
	cfg.dstmac[1] = 11
	cfg.dstmac[2] = 22
	cfg.dstmac[3] = 33
	cfg.dstmac[4] = 44
	cfg.dstmac[5] = 55

	ret := Npa_setmacentry(portid, cfg)
	if ret != 0 {
		fmt.Printf("Npa_setmacentry Fail \n")
		return -1
	}
	ret = common.Com_sendpcap(npa_iface, npa_pcappath+testpcap[testindex], npa_fast)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat := Npa_getstat(portid)
	if ret != 0 {
		fmt.Printf("Npa_getstat Fail \n")
		return -1
	}
	if stat.ModSrcMacPackets == 0 || stat.ModDstMacPackets == 0 {
		fmt.Printf("ModSrcMacPackets ModDstMacPackets Fail \n")
		return -1
	}

	Npa_clrstat(portid)

	ret = Npa_clrmacentry(portid)
	if ret != 0 {
		fmt.Printf("Npa_clrmacentry Fail \n")
		return -1
	}
	ret = common.Com_sendpcap(npa_iface, npa_pcappath+testpcap[testindex], npa_fast)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat = Npa_getstat(portid)
	if ret != 0 {
		fmt.Printf("Npa_getstat Fail \n")
		return -1
	}
	if stat.ModSrcMacPackets != 0 && stat.ModDstMacPackets != 0 {
		fmt.Printf("ModSrcMacPackets ModDstMacPackets Fail \n")
		return -1
	}
	return 0
}

func Npa_TestPacketDedup(portid uint16, dedupflag uint64, testindex uint64) int {
	Npa_clrstat(portid)

	ret := Npa_CfgDedup(portid, dedupflag, 10)
	if ret != 0 {
		fmt.Printf("Npa Dedup Test: get dedup cfg Fail \n")
		return -1
	}
	ret = common.Com_sendpcap(npa_iface, npa_pcappath+testpcap[testindex], npa_fast)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat := Npa_getstat(portid)
	if ret != 0 {
		fmt.Printf("Npa_getstat Fail \n")
		return -1
	}
	if stat.DedupDropPackets == 0 {
		fmt.Printf("DedupDropPackets Fail \n")
		return -1
	}

	Npa_clrstat(portid)

	ret = Npa_CfgDedup(portid, 0, 0)
	if ret != 0 {
		fmt.Printf("Npa Dedup Test: get dedup cfg Fail \n")
		return -1
	}
	ret = common.Com_sendpcap(npa_iface, npa_pcappath+testpcap[testindex], npa_fast)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat = Npa_getstat(portid)
	if ret != 0 {
		fmt.Printf("Npa_getstat Fail \n")
		return -1
	}
	if stat.DedupDropPackets != 0 {
		fmt.Printf("DedupDropPackets Fail \n")
		return -1
	}
	return 0
}

func Npa_TestPacketAcl(portid uint16, testindex uint64) int {
	var fname string
	var cfg AclCfg

	fname = npa_pcappath + testpcap[testindex]
	Npa_clrstat(portid)

	ret, SrcIp, DstIp, SrcPort, DstPort, Protocol := common.Com_getpcapinfo(fname)

	cfg.SrcIp = SrcIp
	cfg.SrcIpMask = 0xffffffff
	cfg.DstIp = DstIp
	cfg.DstIpMask = 0xffffffff
	cfg.SrcPortMin = SrcPort
	cfg.SrcPortMax = SrcPort
	cfg.DstPortMin = DstPort
	cfg.DstPortMax = DstPort
	cfg.Index = 0
	cfg.Protocol = Protocol
	cfg.ActionType = ACL_ACTION_DROP
	cfg.PortId = portid

	ret = Npa_addacl(cfg)
	if ret != 0 {
		fmt.Printf("Npa_add acl fail \n")
		return -1
	}

	ret = common.Com_sendpcap(npa_iface, fname, npa_fast)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat := Npa_getstat(portid)
	if ret != 0 {
		fmt.Printf("Npa_getstat Fail \n")
		return -1
	}
	if stat.AclDropPackets == 0 {
		fmt.Printf("AclDropPackets Fail \n")
		return -1
	}

	ret = Npa_delacl(cfg.PortId, cfg.Index)
	if ret != 0 {
		fmt.Printf("Npa_delacl fail \n")
		return -1
	}
	Npa_clrstat(portid)
	ret = common.Com_sendpcap(npa_iface, fname, npa_fast)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat = Npa_getstat(portid)
	if ret != 0 {
		fmt.Printf("Npa_getstat Fail \n")
		return -1
	}
	if stat.AclDropPackets != 0 {
		fmt.Printf("AclDropPackets Fail \n")
		return -1
	}

	return 0
}

func Npa_TestPacket(portid uint16) int {
	var ret int = 0

	for index := NPA_TEST_ACL; index <= NPA_TEST_MAC_MODIFED; index++ {
		switch index {
		case NPA_TEST_ACL:
			ret = Npa_TestPacketAcl(portid, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_ACL Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_ACL Success \n")
			}
		case NPA_TEST_DEDUP_NO_IGNORE:
			ret = Npa_TestPacketDedup(portid, 0, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_DEDUP_NO_IGNORE Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_DEDUP_NO_IGNORE Success \n")
			}
		case NPA_TEST_DEDUP_IGNORE_MAC:
			ret = Npa_TestPacketDedup(portid, Dedup_ignore_mac, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_MAC Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_MAC Success \n")
			}
		case NPA_TEST_DEDUP_IGNORE_TTL:
			ret = Npa_TestPacketDedup(portid, Dedup_ignore_ttl, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_TTL Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_TTL Success \n")
			}
		case NPA_TEST_DEDUP_IGNORE_SRCIP:
			ret = Npa_TestPacketDedup(portid, Dedup_ignore_srcip, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_SRCIP Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_SRCIP Success \n")
			}
		case NPA_TEST_DEDUP_IGNORE_DSTIP:
			ret = Npa_TestPacketDedup(portid, Dedup_ignore_dstip, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_DSTIP Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_DSTIP Success \n")
			}
		case NPA_TEST_DEDUP_IGNORE_SRCPORT:
			ret = Npa_TestPacketDedup(portid, Dedup_ignore_srcport, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_SRCPORT Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_SRCPORT Success \n")
			}
		case NPA_TEST_DEDUP_IGNORE_DSTPORT:
			ret = Npa_TestPacketDedup(portid, Dedup_ignore_dstport, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_DSTPORT Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_DSTPORT Success \n")
			}
		case NPA_TEST_DEDUP_IGNORE_VXLAN:
			ret = Npa_TestPacketDedup(portid, Dedup_ignore_vxlan, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_VXLAN Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_DEDUP_IGNORE_VXLAN Success \n")
			}
		case NPA_TEST_MAC_MODIFED:
			ret = Npa_TestPacketMac(portid, uint64(index))
			if ret != 0 {
				fmt.Printf("NPA_TEST_MAC_MODIFED Fail \n")
				return -1
			} else {
				fmt.Printf("NPA_TEST_MAC_MODIFED Success \n")
			}
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

	//	for index := NPA_TEST_ACL; index <= NPA_TEST_MAC_MODIFED; index++ {
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
