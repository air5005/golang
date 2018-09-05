package main

import (
	"fmt"
	"npa"
	"os"
	"strconv"
)

var Usage = func() {
	fmt.Println("USAGE: autotest ethname pcap fast")
}

func main() {
	var ret int
	var ethname string
	var pcappath string
	var fast bool

	args := os.Args
	if args == nil || len(args) < 4 {
		Usage()
		return
	}

	for index, value := range args {
		fmt.Printf("args[%d] = %s\n", index, value)
	}

	ethname = args[1]
	pcappath = args[2]
	v1, err1 := strconv.Atoi(args[3])
	if err1 != nil {
		fmt.Println("err")
		return
	}
	if v1 == 0 {
		fast = false
	} else {
		fast = true
	}

	ret = npa.Npa_init(ethname, pcappath, fast)
	fmt.Println("Npa_init: ", ret)
	defer npa.Npa_exit()

	ret = npa.Npa_TestConfig()
	if ret != 0 {
		fmt.Println("Npa_TestConfig fail")
	} else {
		fmt.Println("Npa_TestConfig success")
	}

	ret = npa.Npa_TestPacket(0)
	if ret != 0 {
		fmt.Println("Npa_TestPacket fail")
	} else {
		fmt.Println("Npa_TestPacket success")
	}
}
