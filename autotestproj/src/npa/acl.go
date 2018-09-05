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
	"fmt"
)

const (
	ACL_ACTION_DROP = 1
	ACL_ACTION_FW   = 3
)

type AclCfg struct {
	SrcIp      uint32
	SrcIpMask  uint32
	DstIp      uint32
	DstIpMask  uint32
	SrcPortMin uint16
	SrcPortMax uint16
	DstPortMin uint16
	DstPortMax uint16

	Index      uint32
	Protocol   uint8
	ActionType uint8
	PortId     uint16
}

func Npa_addacl(cfg AclCfg) (ret int) {
	var ret_c C.int
	var cfg_c _Ctype_struct_tag_ST_NPA_ACL_INFO

	cfg_c.uiSrcIp = (C.uint)(cfg.SrcIp)
	cfg_c.uiSrcIpMask = (C.uint)(cfg.SrcIpMask)
	cfg_c.uiDstIp = (C.uint)(cfg.DstIp)
	cfg_c.uiDstIpMask = (C.uint)(cfg.DstIpMask)
	cfg_c.usSrcPortMin = (C.ushort)(cfg.SrcPortMin)
	cfg_c.usSrcPortMax = (C.ushort)(cfg.SrcPortMax)
	cfg_c.usDstPortMin = (C.ushort)(cfg.DstPortMin)
	cfg_c.usDstPortMax = (C.ushort)(cfg.DstPortMax)
	cfg_c.uiIndex = (C.uint)(cfg.Index)
	cfg_c.ucProtocol = (C.uchar)(cfg.Protocol)
	cfg_c.ucActionType = (C.uchar)(cfg.ActionType)
	cfg_c.usPortId = (C.ushort)(cfg.PortId)

	ret_c = C.NpaAddAclEntry(&cfg_c)
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	//	fmt.Println("Npa_addacl dump begin:", ret)
	//	fmt.Printf("srcip:0x%x SrcIpMask:0x%x DstIp:0x%x DstIpMask:0x%x \n", cfg.SrcIp, cfg.SrcIpMask, cfg.DstIp, cfg.DstIpMask)
	//	fmt.Printf("SrcPortMin:%d SrcPortMax:%d DstPortMin:%d DstPortMax:%d \n", cfg.SrcPortMin, cfg.SrcPortMax, cfg.DstPortMin, cfg.DstPortMax)
	//	fmt.Printf("Index:%d Protocol:%d ActionType:%d PortId:%d \n", cfg.Index, cfg.Protocol, cfg.ActionType, cfg.PortId)
	//	fmt.Println("Npa_addacl dump end")

	return ret
}

func Npa_delacl(portid uint16, Index uint32) (ret int) {
	var ret_c C.int

	ret_c = C.NpaDelAclEntry((C.ushort)(portid), (C.uint)(Index))
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	fmt.Println("Npa_delacl:", ret)
	return ret
}

func Npa_modacl(cfg AclCfg) (ret int) {
	var ret_c C.int
	var cfg_c _Ctype_struct_tag_ST_NPA_ACL_INFO

	cfg_c.uiSrcIp = (C.uint)(cfg.SrcIp)
	cfg_c.uiSrcIpMask = (C.uint)(cfg.SrcIpMask)
	cfg_c.uiDstIp = (C.uint)(cfg.DstIp)
	cfg_c.uiDstIpMask = (C.uint)(cfg.DstIpMask)
	cfg_c.usSrcPortMin = (C.ushort)(cfg.SrcPortMin)
	cfg_c.usSrcPortMax = (C.ushort)(cfg.SrcPortMax)
	cfg_c.usDstPortMin = (C.ushort)(cfg.DstPortMin)
	cfg_c.usDstPortMax = (C.ushort)(cfg.DstPortMax)
	cfg_c.uiIndex = (C.uint)(cfg.Index)
	cfg_c.ucProtocol = (C.uchar)(cfg.Protocol)
	cfg_c.ucActionType = (C.uchar)(cfg.ActionType)
	cfg_c.usPortId = (C.ushort)(cfg.PortId)

	ret_c = C.NpaModAclEntry(&cfg_c)
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	//	fmt.Println("Npa_modacl dump begin:", ret)
	//	fmt.Printf("srcip:0x%x SrcIpMask:0x%x DstIp:0x%x DstIpMask:0x%x \n", cfg.SrcIp, cfg.SrcIpMask, cfg.DstIp, cfg.DstIpMask)
	//	fmt.Printf("SrcPortMin:%d SrcPortMax:%d DstPortMin:%d DstPortMax:%d \n", cfg.SrcPortMin, cfg.SrcPortMax, cfg.DstPortMin, cfg.DstPortMax)
	//	fmt.Printf("Index:%d Protocol:%d ActionType:%d PortId:%d \n", cfg.Index, cfg.Protocol, cfg.ActionType, cfg.PortId)
	//	fmt.Println("Npa_modacl dump end")

	return ret
}

func Npa_getacl(portid uint16, Index uint32) (ret int, cfg AclCfg) {
	var ret_c C.int
	var cfg_c _Ctype_struct_tag_ST_NPA_ACL_INFO

	cfg_c.usPortId = (C.ushort)(portid)
	cfg_c.uiIndex = (C.uint)(Index)
	ret_c = C.NpaGetAclEntry(&cfg_c)
	if ret_c != 0 {
		ret = -1
	} else {
		ret = 0
	}

	cfg.SrcIp = (uint32)(cfg_c.uiSrcIp)
	cfg.SrcIpMask = (uint32)(cfg_c.uiSrcIpMask)
	cfg.DstIp = (uint32)(cfg_c.uiDstIp)
	cfg.DstIpMask = (uint32)(cfg_c.uiDstIpMask)
	cfg.SrcPortMin = (uint16)(cfg_c.usSrcPortMin)
	cfg.SrcPortMax = (uint16)(cfg_c.usSrcPortMax)
	cfg.DstPortMin = (uint16)(cfg_c.usDstPortMin)
	cfg.DstPortMax = (uint16)(cfg_c.usDstPortMax)
	cfg.Index = (uint32)(cfg_c.uiIndex)
	cfg.Protocol = (uint8)(cfg_c.ucProtocol)
	cfg.ActionType = (uint8)(cfg_c.ucActionType)
	cfg.PortId = (uint16)(cfg_c.usPortId)

	//	fmt.Println("Npa_getacl dump begin:", ret)
	//	fmt.Printf("srcip:0x%x SrcIpMask:0x%x DstIp:0x%x DstIpMask:0x%x \n", cfg.SrcIp, cfg.SrcIpMask, cfg.DstIp, cfg.DstIpMask)
	//	fmt.Printf("SrcPortMin:%d SrcPortMax:%d DstPortMin:%d DstPortMax:%d \n", cfg.SrcPortMin, cfg.SrcPortMax, cfg.DstPortMin, cfg.DstPortMax)
	//	fmt.Printf("Index:%d Protocol:%d ActionType:%d PortId:%d \n", cfg.Index, cfg.Protocol, cfg.ActionType, cfg.PortId)
	//	fmt.Println("Npa_getacl dump end")

	return ret, cfg
}
