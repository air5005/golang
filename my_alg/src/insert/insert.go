package insert

/*
	var array = make([]int, 100, 100)

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

	insert.Sort1(array, arraylen)

	for index := 0; index < arraylen; index++ {
		fmt.Printf("after array[%d] = %d \r\n", index, array[index])
	}

	insert.Sort2(array, arraylen)

	for index := 0; index < arraylen; index++ {
		fmt.Printf("after array[%d] = %d \r\n", index, array[index])
	}
*/
import (
	"swap"
)

func Sort1(a []int, arraylen int) {
	for i := 1; i < arraylen; i++ {
		for j := i; j > 0; j-- {
			if a[j] < a[j-1] {
				swap.Swap2(a, j, j-1)
			}
		}
	}
}

func Sort2(a []int, arraylen int) {
	for i := 1; i < arraylen; i++ {
		for j := i; j > 0; j-- {
			if a[j] > a[j-1] {
				swap.Swap2(a, j, j-1)
			}
		}
	}
}
