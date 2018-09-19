package quick

import "swap"

func partition(a []int, l, r int) int {
	x := a[l]

	for {
		for {
			if a[r] < x {
				break
			}
			r--
		}
		for {
			if a[l] > x {
				break
			}
			l++
		}

		if l >= r {
			break
		}
		swap.Swap2(a, l, r)
	}
	return l
}

func Sort(a []int, l, r int) {
	if l < r {
		q := partition(a, l, r)
		Sort(a, l, q-1)
		Sort(a, q+1, r)
	}
}
