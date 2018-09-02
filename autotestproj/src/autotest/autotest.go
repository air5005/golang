package main

/*
#cgo CFLAGS: -I. -I/home/ych/zr9101/install/npa/lib/include/
#cgo LDFLAGS:-L/home/ych/zr9101/install/npa/lib/ -lstdc++ -lc -lpthread -ldl -lnpa
#include "platform.h"
#include "NpaLib.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "SncpServer.h"
#include "common.h"
*/
import "C"

//import "unsafe"

import (
	"common"
	"fmt"
	"os"
	"strconv"
)

var Usage = func() {
	fmt.Println("USAGE: autotest ...")
}

func main() {
	args := os.Args
	if args == nil || len(args) < 2 {
		Usage()
		return
	}

	C.Cm_NicIsOnLine()

	for index, value := range args {
		fmt.Printf("args[%d] = %s\n", index, value)
	}

	switch args[1] {
	case "common":
		fmt.Println("enter: ", args[1])
		if len(args) != 4 {
			fmt.Println("USAGE: err 1")
			return
		}
		v1, err1 := strconv.Atoi(args[2])
		v2, err2 := strconv.Atoi(args[3])
		if err1 != nil || err2 != nil {
			fmt.Println("USAGE: err 2")
			return
		}
		common.Com_print(v1, v2)
		common.Go_packet()
	case "npa":
		fmt.Println("enter: ", args[1])
	case "ppp":
		fmt.Println("enter: ", args[1])
	case "gopacket":
		fmt.Println("enter: ", args[1])
	default:
		Usage()
	}

}
