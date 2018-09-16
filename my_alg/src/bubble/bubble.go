package bubble

import (
	"swap"
)

func Method1(array []int, arraylen int) {
	for i := 0; i < arraylen-1; i++ {
		for j := 0; j < arraylen-1-i; j++ {
			if array[j] < array[j+1] {
				swap.Swap2(array, j, j+1)
			}
		}
	}
}
