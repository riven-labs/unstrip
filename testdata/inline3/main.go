package main

import (
	"fmt"
	"os"
)

// Three layers of inlined helpers feeding into one another. //go:noinline on
// main so it stays the physical anchor; nothing else is annotated, so the Go
// compiler is free to inline level1 into level2 into level3 into main.

func level3(x int) int {
	return x*x + 1
}

func level2(x int) int {
	return level3(x) + level3(x+1)
}

func level1(x int) int {
	return level2(x) * 2
}

//go:noinline
func anchor(x int) int {
	return level1(x) + level1(x*3)
}

func main() {
	if len(os.Args) > 1 {
		fmt.Println(anchor(7))
		return
	}
	fmt.Println(anchor(3))
}
