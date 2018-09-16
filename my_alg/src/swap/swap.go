package swap

func Swap1(array []int, a, b int) {
	tmp := array[a]
	array[a] = array[b]
	array[a] = tmp
}

func Swap2(array []int, a, b int) {
	array[a] = array[a] + array[b]
	array[b] = array[a] - array[b]
	array[a] = array[a] - array[b]
}
