// Build with multiple Go releases to pin type and itab recovery across the
// pclntab/moduledata layout changes. No generics, so it builds on Go 1.16+.
package main

import "fmt"

type Codec interface {
	Apply(b []byte) []byte
	Name() string
}

type xorCodec struct {
	Key  byte
	Tag  string
}

func (x xorCodec) Apply(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ x.Key
	}
	return out
}
func (x xorCodec) Name() string { return "xor:" + x.Tag }

type addCodec struct {
	Delta int
}

func (a addCodec) Apply(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c + byte(a.Delta)
	}
	return out
}
func (a addCodec) Name() string { return fmt.Sprintf("add:%d", a.Delta) }

func run(c Codec, data []byte) {
	fmt.Println(c.Name(), c.Apply(data))
}

func main() {
	codecs := []Codec{xorCodec{Key: 0x5a, Tag: "k1"}, addCodec{Delta: 3}}
	for _, c := range codecs {
		run(c, []byte("payload"))
	}
}
