// A richer fixture than hello.go: it exercises interfaces and itabs, generics,
// structs with value and pointer receivers, goroutines, and a stdlib crypto
// dependency. Built with each Go release so the integration tests can pin type,
// itab, and signature recovery across the whole supported version range, not
// just function names. Kept to 1.18-compatible constructs (generics yes; the
// 1.21 builtins min/max/clear and range-over-func no) so every release builds it.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
)

// An interface with several concrete implementers: the source of the itabs the
// recovery tests assert on.
type Codec interface {
	Encode(b []byte) []byte
	Name() string
}

type xorCodec struct{ key byte }

func (c xorCodec) Encode(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[i] = b[i] ^ c.key
	}
	return o
}
func (c xorCodec) Name() string { return "xor" }

type addCodec struct{ delta byte }

func (c addCodec) Encode(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[i] = b[i] + c.delta
	}
	return o
}
func (c addCodec) Name() string { return "add" }

// Generics: a set and a map helper, instantiated below so the compiler emits
// shape-stenciled code the type walker has to handle.
type Set[T comparable] struct{ m map[T]struct{} }

func NewSet[T comparable]() *Set[T] { return &Set[T]{m: make(map[T]struct{})} }
func (s *Set[T]) Add(v T)           { s.m[v] = struct{}{} }
func (s *Set[T]) Len() int          { return len(s.m) }

func mapEach[T, U any](in []T, f func(T) U) []U {
	out := make([]U, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}

// A struct with both a value and a pointer receiver method, and a few field
// types, so struct-field recovery has something to chew on.
type Record struct {
	ID   int
	Name string
	Tags []string
}

func (r Record) summary() string  { return fmt.Sprintf("%d:%s", r.ID, r.Name) }
func (r *Record) addTag(t string) { r.Tags = append(r.Tags, t) }

//go:noinline
func run(codecs []Codec, data []byte) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := make([]string, len(codecs))
	for i, c := range codecs {
		wg.Add(1)
		go func(i int, c Codec) {
			defer wg.Done()
			enc := c.Encode(data)
			sum := sha256.Sum256(enc)
			mu.Lock()
			out[i] = c.Name() + ":" + hex.EncodeToString(sum[:4])
			mu.Unlock()
		}(i, c)
	}
	wg.Wait()
	sort.Strings(out)
	return out
}

func main() {
	codecs := []Codec{xorCodec{0x5b}, addCodec{3}}
	results := run(codecs, []byte("payload data goes here"))
	set := NewSet[string]()
	for _, r := range results {
		set.Add(r)
	}
	rec := &Record{ID: 1, Name: "first"}
	rec.addTag("a")
	names := mapEach(codecs, func(c Codec) string { return c.Name() })
	fmt.Println(results, set.Len(), rec.summary(), names)
}
