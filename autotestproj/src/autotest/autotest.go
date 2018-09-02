package main

import (
	"common"
	"fmt"
	"npa"
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
		ret := npa.Npa_init()
		fmt.Println("Npa_init: ", ret)
	case "ppp":
		fmt.Println("enter: ", args[1])
	case "gopacket":
		fmt.Println("enter: ", args[1])
	default:
		Usage()
	}

}
