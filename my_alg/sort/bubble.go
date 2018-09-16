package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	var array [100]int

	args := os.Args
	if args == nil || len(args) >= 100 {
		fmt.Println("inut para is null or args too much")
		return
	}

	arraylen := len(args) - 1
	for index := 0; index < arraylen; index++ {
		array[index], _ = strconv.Atoi(args[index+1])
	}

	fmt.Println("arraylen:", arraylen)
	for index := 0; index < arraylen; index++ {
		fmt.Printf("before array[%d] = %d \r\n", index, array[index])
	}

	for i := 0; i < arraylen-1; i++ {
		for j := 0; j < arraylen-1-i; j++ {
			if array[j] < array[j+1] {
				array[j] = array[j] + array[j+1]
				array[j+1] = array[j] - array[j+1]
				array[j] = array[j] - array[j+1]
			}
		}
	}

	for index := 0; index < arraylen; index++ {
		fmt.Printf("after array[%d] = %d \r\n", index, array[index])
	}

	return
}
