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
const Npa_max_card_num = 1

type NpaTestCfgInfo struct {
	npa_iface    [Npa_max_port_num]string
	npa_pcappath [Npa_max_port_num]string
}

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

var testpara = []NpaTestCfgInfo{
	NpaTestCfgInfo{
		npa_iface:    [Npa_max_port_num]string{"p4p1_0", "p4p2_0"},
		npa_pcappath: [Npa_max_port_num]string{"/home/ych/pcap/", "/home/ych/pcap/"},
	},
	NpaTestCfgInfo{
		npa_iface:    [Npa_max_port_num]string{"p2p1_0", "p2p2_0"},
		npa_pcappath: [Npa_max_port_num]string{"/home/ych/pcap/", "/home/ych/pcap/"},
	},
}

func NpaDumpTestPara() {
	fmt.Println(testpara[0].npa_iface[0])
	fmt.Println(testpara[0].npa_pcappath[0])
	fmt.Println(testpara[0].npa_iface[1])
	fmt.Println(testpara[0].npa_pcappath[1])
	fmt.Println(testpara[1].npa_iface[0])
	fmt.Println(testpara[1].npa_pcappath[0])
	fmt.Println(testpara[1].npa_iface[1])
	fmt.Println(testpara[1].npa_pcappath[1])
}

func Npa_TestConfig() int {
	var decfg DedupCfg
	var macentry MacCfg
	var cardid uint16
	var portid uint16

	for cardid = 0; cardid < Npa_max_card_num; cardid++ {
		for portid = 0; portid < Npa_max_port_num; portid++ {
			//test dedup config
			decfg.dedupflag = Dedup_ignore_mac | Dedup_ignore_ttl | Dedup_ignore_srcip |
				Dedup_ignore_dstip | Dedup_ignore_proto | Dedup_ignore_srcport |
				Dedup_ignore_dstport | Dedup_ignore_vxlan
			decfg.timeout = 100

			ret := Npa_setdedup(cardid, portid, decfg)
			if ret != 0 {
				fmt.Printf("Npa Dedup Test: set dedup cfg Fail \n")
				return ret
			}

			ret, respdecfg := Npa_getdedup(cardid, portid)
			if ret != 0 {
				fmt.Printf("Npa Dedup Test: get dedup cfg Fail \n")
				return ret
			}

			if decfg.dedupflag != respdecfg.dedupflag || decfg.timeout != respdecfg.timeout {
				fmt.Printf("Npa Dedup Test: get dedup cfg data Fail \n")
				return ret
			}

			ret = Npa_clrdedup(cardid, portid)
			if ret != 0 {
				fmt.Printf("Npa Dedup Test: clr dedup cfg Fail \n")
				return ret
			}

			ret, respdecfg = Npa_getdedup(cardid, portid)
			if respdecfg.dedupflag != 0 || respdecfg.timeout != 0 {
				fmt.Printf("Npa Dedup Test: clr dedup cfg data Fail \n")
				return ret
			}

			fmt.Printf("card:%d, port:%d, Npa Dedup config Test Success\n", cardid, portid)
		}
	}

	//test modifed mac config
	for cardid = 0; cardid < Npa_max_card_num; cardid++ {
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
			ret := Npa_setmacentry(cardid, portid, macentry)
			if ret != 0 {
				fmt.Printf("Npa modifed mac Test: set dedup cfg Fail \n")
				return ret
			}

			ret, respmacentry := Npa_getmacentry(cardid, portid)
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

			ret = Npa_clrmacentry(cardid, portid)
			if ret != 0 {
				fmt.Printf("Npa modifed mac Test: clr dedup cfg Fail \n")
				return ret
			}

			ret, respmacentry = Npa_getmacentry(cardid, portid)
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

			fmt.Printf("card:%d, port:%d, Npa modifed mac config Test Success\n", cardid, portid)
		}
	}

	//test modifed acl config
	for cardid = 0; cardid < Npa_max_card_num; cardid++ {
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
			cfg.CardId = cardid

			ret := Npa_addacl(cfg)
			if ret != 0 {
				fmt.Printf("Npa_add acl fail \n")
				return -1
			}

			ret, respcfg := Npa_getacl(cardid, portid, cfg.Index)
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
				cfg.PortId != respcfg.PortId ||
				cfg.CardId != respcfg.CardId {
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
			cfg.CardId = cardid

			ret = Npa_modacl(cfg)
			if ret != 0 {
				fmt.Printf("Npa_modacl fail \n")
				return -1
			}

			ret, respcfg = Npa_getacl(cardid, portid, cfg.Index)
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
				cfg.PortId != respcfg.PortId ||
				cfg.CardId != respcfg.CardId {
				fmt.Printf("Npa_getacl data fail \n")
				return -1
			}

			ret = Npa_delacl(cardid, portid, cfg.Index)
			if ret != 0 {
				fmt.Printf("Npa_delacl fail \n")
				return -1
			}

			ret, _ = Npa_getacl(cardid, portid, cfg.Index)
			if ret == 0 {
				fmt.Printf("Npa_getacl fail \n")
				return -1
			}

			fmt.Printf("card:%d, port:%d, Npa acl config Test Success \n", cardid, portid)
		}
	}

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

func Npa_CfgDedup(cardid uint16, portid uint16, dedupflag uint64, timeout uint64) int {
	var decfg DedupCfg

	if cardid >= Npa_max_card_num || portid >= Npa_max_port_num {
		fmt.Println("Inpara Err, portid:", portid, "dedupflag:", dedupflag)
		return -1
	}
	ret := Npa_clrdedup(cardid, portid)
	if ret != 0 {
		fmt.Printf("Npa Dedup Test: clr dedup cfg Fail \n")
		return -1
	}
	decfg.dedupflag = dedupflag
	decfg.timeout = timeout
	ret = Npa_setdedup(cardid, portid, decfg)
	if ret != 0 {
		fmt.Printf("Npa Dedup Test: set dedup cfg Fail \n")
		return -1
	}
	ret, respdecfg := Npa_getdedup(cardid, portid)
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

func Npa_TestPacketMac(cardid uint16, portid uint16, testindex uint64) int {
	var cfg MacCfg

	Npa_clrstat(cardid, portid)

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

	ret := Npa_setmacentry(cardid, portid, cfg)
	if ret != 0 {
		fmt.Printf("Npa_setmacentry Fail \n")
		return -1
	}
	ret = common.Com_sendpcap(testpara[cardid].npa_iface[portid], testpara[cardid].npa_pcappath[portid]+testpcap[testindex], true)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat := Npa_getstat(cardid, portid)
	if ret != 0 {
		fmt.Printf("Npa_getstat Fail \n")
		return -1
	}
	if stat.ModSrcMacPackets == 0 || stat.ModDstMacPackets == 0 {
		fmt.Printf("ModSrcMacPackets ModDstMacPackets Fail \n")
		return -1
	}

	Npa_clrstat(cardid, portid)

	ret = Npa_clrmacentry(cardid, portid)
	if ret != 0 {
		fmt.Printf("Npa_clrmacentry Fail \n")
		return -1
	}
	ret = common.Com_sendpcap(testpara[cardid].npa_iface[portid], testpara[cardid].npa_pcappath[portid]+testpcap[testindex], true)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat = Npa_getstat(cardid, portid)
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

func Npa_TestPacketDedup(cardid uint16, portid uint16, dedupflag uint64, testindex uint64) int {
	Npa_clrstat(cardid, portid)

	ret := Npa_CfgDedup(cardid, portid, dedupflag, 10)
	if ret != 0 {
		fmt.Printf("Npa Dedup Test: get dedup cfg Fail \n")
		return -1
	}
	ret = common.Com_sendpcap(testpara[cardid].npa_iface[portid], testpara[cardid].npa_pcappath[portid]+testpcap[testindex], true)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat := Npa_getstat(cardid, portid)
	if ret != 0 {
		fmt.Printf("Npa_getstat Fail \n")
		return -1
	}
	if stat.DedupDropPackets == 0 {
		fmt.Printf("DedupDropPackets Fail \n")
		return -1
	}

	Npa_clrstat(cardid, portid)

	ret = Npa_CfgDedup(cardid, portid, 0, 0)
	if ret != 0 {
		fmt.Printf("Npa Dedup Test: get dedup cfg Fail \n")
		return -1
	}
	ret = common.Com_sendpcap(testpara[cardid].npa_iface[portid], testpara[cardid].npa_pcappath[portid]+testpcap[testindex], true)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat = Npa_getstat(cardid, portid)
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

func Npa_TestPacketAcl(cardid uint16, portid uint16, testindex uint64) int {
	var fname string
	var cfg AclCfg

	fname = testpara[cardid].npa_pcappath[portid] + testpcap[testindex]
	Npa_clrstat(cardid, portid)

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
	cfg.CardId = cardid

	ret = Npa_addacl(cfg)
	if ret != 0 {
		fmt.Printf("Npa_add acl fail \n")
		return -1
	}

	ret = common.Com_sendpcap(testpara[cardid].npa_iface[portid], fname, true)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat := Npa_getstat(cardid, portid)
	if ret != 0 {
		fmt.Printf("Npa_getstat Fail \n")
		return -1
	}
	if stat.AclDropPackets == 0 {
		fmt.Printf("AclDropPackets Fail \n")
		return -1
	}

	ret = Npa_delacl(cardid, portid, cfg.Index)
	if ret != 0 {
		fmt.Printf("Npa_delacl fail \n")
		return -1
	}
	Npa_clrstat(cardid, portid)
	ret = common.Com_sendpcap(testpara[cardid].npa_iface[portid], fname, true)
	if ret != 0 {
		fmt.Printf("Com_sendpcap Fail \n")
		return -1
	}
	ret, stat = Npa_getstat(cardid, portid)
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

func Npa_TestPacket() int {
	var ret int = 0
	var cardid uint16
	var portid uint16

	for cardid = 0; cardid < Npa_max_card_num; cardid++ {
		for portid = 0; portid < Npa_max_port_num; portid++ {
			for index := NPA_TEST_ACL; index <= NPA_TEST_MAC_MODIFED; index++ {
				switch index {
				case NPA_TEST_ACL:
					ret = Npa_TestPacketAcl(cardid, portid, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_ACL Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_ACL Success \n", cardid, portid)
					}
				case NPA_TEST_DEDUP_NO_IGNORE:
					ret = Npa_TestPacketDedup(cardid, portid, 0, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_NO_IGNORE Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_NO_IGNORE Success \n", cardid, portid)
					}
				case NPA_TEST_DEDUP_IGNORE_MAC:
					ret = Npa_TestPacketDedup(cardid, portid, Dedup_ignore_mac, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_MAC Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_MAC Success \n", cardid, portid)
					}
				case NPA_TEST_DEDUP_IGNORE_TTL:
					ret = Npa_TestPacketDedup(cardid, portid, Dedup_ignore_ttl, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_TTL Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_TTL Success \n", cardid, portid)
					}
				case NPA_TEST_DEDUP_IGNORE_SRCIP:
					ret = Npa_TestPacketDedup(cardid, portid, Dedup_ignore_srcip, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_SRCIP Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_SRCIP Success \n", cardid, portid)
					}
				case NPA_TEST_DEDUP_IGNORE_DSTIP:
					ret = Npa_TestPacketDedup(cardid, portid, Dedup_ignore_dstip, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_DSTIP Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_DSTIP Success \n", cardid, portid)
					}
				case NPA_TEST_DEDUP_IGNORE_SRCPORT:
					ret = Npa_TestPacketDedup(cardid, portid, Dedup_ignore_srcport, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_SRCPORT Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_SRCPORT Success \n", cardid, portid)
					}
				case NPA_TEST_DEDUP_IGNORE_DSTPORT:
					ret = Npa_TestPacketDedup(cardid, portid, Dedup_ignore_dstport, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_DSTPORT Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_DSTPORT Success \n", cardid, portid)
					}
				case NPA_TEST_DEDUP_IGNORE_VXLAN:
					ret = Npa_TestPacketDedup(cardid, portid, Dedup_ignore_vxlan, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_VXLAN Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_DEDUP_IGNORE_VXLAN Success \n", cardid, portid)
					}
				case NPA_TEST_MAC_MODIFED:
					ret = Npa_TestPacketMac(cardid, portid, uint64(index))
					if ret != 0 {
						fmt.Printf("card:%d, port:%d, NPA_TEST_MAC_MODIFED Fail \n", cardid, portid)
						return -1
					} else {
						fmt.Printf("card:%d, port:%d, NPA_TEST_MAC_MODIFED Success \n", cardid, portid)
					}
				default:
					fmt.Println("card:%d, port:%d, err para, index:", cardid, portid, index)
				}
			}
		}
	}

	return 0
}

func Npa_init() int {
	var ret_c C.int

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
