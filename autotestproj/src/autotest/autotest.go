package main

import (
	"common"
	"fmt"
	"npa"
	"os"
	"os/signal"
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

	fmt.Println("enter: ", args[1])
	switch args[1] {
	case "common":
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
		go common.Com_task()
	case "npa":
		ret := npa.Npa_init()
		fmt.Println("Npa_init: ", ret)

		ret = npa.Npa_TestConfig()
		if ret != 0 {
			fmt.Println("Npa_TestConfig fail")
		} else {
			fmt.Println("Npa_TestConfig success")
			return
		}
	case "ppp":
	case "gopacket":
	default:
		Usage()
	}

	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for _ = range signalChan {
			fmt.Println("exit: ", args[1])
			switch args[1] {
			case "common":
			case "npa":
				npa.Npa_exit()
			case "ppp":
			case "gopacket":
			default:

			}
			cleanupDone <- true
		}
	}()
	<-cleanupDone
}
