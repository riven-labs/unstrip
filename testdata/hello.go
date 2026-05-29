package main

import (
	"fmt"
	"os"
)

//go:noinline
func greet(name string) string {
	return fmt.Sprintf("hello, %s", name)
}

//go:noinline
func parseFlags(args []string) (string, error) {
	if len(args) < 2 {
		return "world", nil
	}
	return args[1], nil
}

func main() {
	name, err := parseFlags(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(greet(name))
}
