// methodset.go pins method-table recovery (the [Mcount]Method array behind
// each named type's UncommonType) for every kind a named type with methods can
// have. The UncommonType sits after the kind's whole XxxType struct, so each
// kind puts it at a different offset; maps changed shape in Go 1.24 (swiss
// tables). It uses no generics so it builds with Go 1.17.
package main

import (
	"fmt"
	"os"
)

type shower interface {
	Show(prefix string) string
}

type Handler func(string) int

func (h Handler) Show(prefix string) string { return fmt.Sprint(prefix, h(prefix)) }

type Header map[string][]string

func (h Header) Show(prefix string) string { return fmt.Sprint(prefix, len(h[prefix])) }

type Pipe chan int

func (p Pipe) Show(prefix string) string { return fmt.Sprint(prefix, cap(p)) }

type Quad [4]int

func (q Quad) Show(prefix string) string { return fmt.Sprint(prefix, q[0]+q[3]) }

type Names []string

func (n Names) Show(prefix string) string { return fmt.Sprint(prefix, len(n)) }

type Celsius float64

func (c Celsius) Show(prefix string) string { return fmt.Sprint(prefix, float64(c)+273.15) }

type Label string

func (l Label) Show(prefix string) string { return prefix + string(l) }

type Box struct{ v int }

func (b *Box) Show(prefix string) string { return fmt.Sprint(prefix, b.v) }

func main() {
	items := []shower{
		Handler(func(s string) int { return len(s) }),
		Header{"a": {"b"}},
		make(Pipe, len(os.Args)),
		Quad{1, 2, 3, len(os.Args)},
		Names(os.Args),
		Celsius(len(os.Args)),
		Label(os.Args[0]),
		&Box{v: len(os.Args)},
	}
	for _, it := range items {
		fmt.Println(it.Show("x"))
	}
}
