package main

import "github.com/buptmiao/parallel"

func testJobA(x, y int) int {
	return x - y
}

func testJobB(x, y int) int {
	return x + y
}

func testJobC(x, y *int, z int) float64 {
	return float64((*x)*(*y)) / float64(z)
}

func main() {
	var x, y int
	var z float64

	p := parallel.NewParallel()

	ch1 := p.NewChild()
	ch1.Register(testJobA, 1, 2).SetReceivers(&x)

	ch2 := p.NewChild()
	ch2.Register(testJobB, 1, 2).SetReceivers(&y)

	p.Register(testJobC, &x, &y, 2).SetReceivers(&z)

	p.Run()

	if x != -1 || y != 3 || z != -1.5 {
		panic("unexpected result")
	}
}
