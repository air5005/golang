package main

import (
	"common"
	"fmt"
	"os"
)

/*
#cgo CFLAGS: -I. -I/home/ych/zr9101/install/npa/lib/include/
#cgo LDFLAGS: /home/ych/zr9101/install/npa/lib/libnpa.a -lstdc++ -lc -lpthread -ldl
#include "platform.h"
#include "NpaLib.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "SncpServer.h"
*/
import "C"

var Usage = func() {
	fmt.Println("USAGE: autotest ...")
}

func main() {
	args := os.Args
	if args == nil || len(args) < 2 {
		Usage()
		return
	}

	for index, value := range args {
		fmt.Printf("args[%d] = %s\n", index, value)
	}

	common.Com_print(5, 6)
	C.Cm_NicIsOnLine()
}
