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

	args := os.Args
	if args == nil || len(args) < 2 {
		Usage()
		return
	}

	for index, value := range args {
		fmt.Printf("args[%d] = %s\n", index, value)
	}

	testtype, err1 := strconv.Atoi(args[1])
	if err1 != nil {
		fmt.Println("err")
		return
	}

	switch testtype {
	case 0:
		ret = npa.Npa_init()
		fmt.Println("Npa_init: ", ret)
		defer npa.Npa_exit()

		ret = npa.Npa_TestConfig()
		if ret != 0 {
			fmt.Println("Npa_TestConfig fail")
			return
		} else {
			fmt.Println("Npa_TestConfig success")
		}

		ret = npa.Npa_TestPacket()
		if ret != 0 {
			fmt.Println("Npa_TestPacket fail")
			return
		} else {
			fmt.Println("Npa_TestPacket success")
		}
	default:
	}

}
