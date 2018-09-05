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

	return ret
}
