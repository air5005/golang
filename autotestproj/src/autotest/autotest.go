package main

import (
	"common"
	"fmt"
	"npa"
	"os"
	//	"os/signal"
	"strconv"
)

var Usage = func() {
	fmt.Println("USAGE: autotest ...")
}

func main() {
	var ret int
	var fast bool

	args := os.Args
	if args == nil || len(args) < 2 {
		Usage()
		return
	}

	for index, value := range args {
		fmt.Printf("args[%d] = %s\n", index, value)
	}

	fmt.Println("enter: ", args[1])
	switch args[1] {
	case "common":
		if len(args) < 5 {
			Usage()
			return
		}
		v1, err1 := strconv.Atoi(args[4])
		if err1 != nil {
			fmt.Println("err")
			return
		}
		if v1 == 0 {
			fast = false
		} else {
			fast = true
		}

		ret = common.Com_sendpcap(args[2], args[3], fast)
		if ret != 0 {
			fmt.Println("Com_sendpcap fail")
		} else {
			fmt.Println("Com_sendpcap success")
		}
	case "npa":
		ret = npa.Npa_init()
		fmt.Println("Npa_init: ", ret)

		ret = npa.Npa_TestConfig()
		if ret != 0 {
			fmt.Println("Npa_TestConfig fail")
		} else {
			fmt.Println("Npa_TestConfig success")
		}

		defer npa.Npa_exit()
	case "ppp":
	case "gopacket":
	default:
		Usage()
	}

	//	signalChan := make(chan os.Signal, 1)
	//	cleanupDone := make(chan bool)
	//	signal.Notify(signalChan, os.Interrupt)
	//	go func() {
	//		for _ = range signalChan {
	//			fmt.Println("exit: ", args[1])
	//			switch args[1] {
	//			case "common":
	//			case "npa":
	//				npa.Npa_exit()
	//			case "ppp":
	//			case "gopacket":
	//			default:

	//			}
	//			cleanupDone <- true
	//		}
	//	}()
	//	<-cleanupDone
}
