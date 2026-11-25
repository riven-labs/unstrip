// strlits.go puts string literals in each shape the Go compiler emits for
// them: call arguments, results, struct fields stored through a pointer,
// composite literals, initialized globals, map literals, switch cases,
// comparisons and concatenations. The `--strings` literal pairing is checked
// against it. It has no generics so it builds with Go 1.15.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Host  string
	Port  int
	Agent string
	Paths []string
}

var endpoints = []string{
	"https://alpha.strlits.example/api/v1",
	"https://bravo.strlits.example/api/v2",
	"https://charlie.strlits.example/upload",
}

var defaultConfig = Config{
	Host:  "static-host.strlits.example",
	Port:  8443,
	Agent: "strlits-agent/1.0 (static)",
}

var banner = "strlits global banner value"

var headers = map[string]string{
	"X-Strlits-Key":   "strlits-map-value-one",
	"X-Strlits-Token": "strlits-map-value-two",
}

//go:noinline
func connect(host string, port int) error {
	if host == "" {
		return errors.New("strlits: empty host given to connect")
	}
	if port <= 0 {
		return fmt.Errorf("strlits: bad port %d for %s", port, host)
	}
	return nil
}

//go:noinline
func describe(kind int) string {
	switch kind {
	case 0:
		return "strlits kind zero"
	case 1:
		return "strlits kind one"
	}
	return "strlits kind unknown"
}

//go:noinline
func classify(s string) int {
	switch s {
	case "strlits-case-alpha":
		return 1
	case "strlits-case-bravo":
		return 2
	case "strlits-case-charlie-longer-value":
		return 3
	}
	if s == "strlits comparison value that is long enough" {
		return 4
	}
	return 0
}

//go:noinline
func build(user string) *Config {
	c := &Config{
		Host:  "dynamic-host.strlits.example",
		Port:  443,
		Agent: "strlits-agent/2.0 (" + user + ")",
	}
	c.Paths = []string{"/strlits/first", "/strlits/second", user}
	return c
}

//go:noinline
func pick(a, b, c string) string {
	if len(a) > len(b) {
		return a + c
	}
	return b + c
}

//go:noinline
func bytesOf() []byte {
	return []byte("strlits bytes literal")
}

func main() {
	c := build(os.Getenv("USER"))
	if err := connect(c.Host, c.Port); err != nil {
		fmt.Fprintln(os.Stderr, "strlits connect failed:", err)
	}
	if err := connect(defaultConfig.Host, defaultConfig.Port); err != nil {
		panic("strlits: static connect failed")
	}
	fmt.Println(describe(len(os.Args)), classify(os.Getenv("STRLITS_MODE")))
	fmt.Println(pick("strlits-pick-a", "strlits-pick-b", "strlits-pick-suffix"))
	fmt.Println(strings.ToUpper("strlits upper me"), len(bytesOf()))
	fmt.Println("strlits non-ascii: héllo wörld", "strlits\x00binary\xff")
	for _, e := range endpoints {
		fmt.Println(e, banner, headers["X-Strlits-Key"])
	}
}
