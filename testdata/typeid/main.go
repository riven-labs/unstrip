// Type identity fixture: struct, interface, map, chan, func and array types
// that reference each other, two types printed as sync.Mutex from different
// packages, and a reflect dump of everything reachable from them. Run the
// binary with `dump` to print one JSON line per type, the ground truth that
// unstrip's --types output is checked against. Builds with Go 1.7 and later.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	isync "typeid/sync"
)

type Item struct {
	ID    int64  `json:"id"`
	Label string `json:"label,omitempty" db:"label"`
	Score float32
}

type Node struct {
	Value int
	Next  *Node
	Kids  []*Node
}

type Config struct {
	C2      string `json:"c2"`
	Port    uint16 `json:"port"`
	Items   []Item
	Headers map[string][]string
	Index   map[int64]*Item
	Root    *Node
	Ring    [4]byte
	Grid    [2][3]int16
	Done    chan struct{}
	Events  <-chan Event
	Sink    chan<- []byte
	Pipes   chan (<-chan int)
	OnError func(error) bool
	Format  func(string, ...interface{}) (int, error)
	Handler Handler
	Any     interface{}
	Inline  struct{ A, B int }
	Tagged  struct {
		X int `x:"1"`
	}
	mu       sync.Mutex
	local    isync.Mutex
	ptrs     []*isync.Mutex
	locks    map[string]*sync.Mutex
	deadline time.Time
	ctx      context.Context
}

type Event struct {
	At   int64
	Kind EventKind
	Data json.RawMessage
}

type EventKind uint8

func (k EventKind) String() string { return fmt.Sprintf("kind%d", uint8(k)) }

type Handler interface {
	Handle([]byte) ([]byte, error)
	Name() string
}

type Closer interface {
	io.Closer
	Handler
	flush(force bool) int
}

type Base struct {
	ID   int
	name string
}

func (b *Base) SetName(s string) { b.name = s }
func (b Base) Name() string      { return b.name }

type Derived struct {
	Base
	*isync.Mutex
	io.Reader
	Extra []string `json:"extra"`
}

type Headers map[string][]string

func (h Headers) Get(k string) string {
	if v := h[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

type Visitor func(n *Node, depth int) bool

func (v Visitor) Walk(n *Node) { v(n, 0) }

type Names []string

func (n Names) Len() int { return len(n) }

type Matrix [3][3]float64

type echo struct{ prefix []byte }

func (e *echo) Handle(b []byte) ([]byte, error) { return append(e.prefix, b...), nil }
func (e *echo) Name() string                    { return "echo" }
func (e *echo) Close() error                    { return nil }
func (e *echo) flush(force bool) int            { return 0 }

type Pair struct {
	Left, Right *sync.Mutex
	Other       *isync.Mutex
}

var roots = []interface{}{
	Config{}, &Config{}, Item{}, &Node{}, Event{}, EventKind(0), Derived{}, &Derived{},
	Headers{}, Visitor(nil), Names{}, Matrix{}, &echo{}, Pair{}, &Base{},
	(*Handler)(nil), (*Closer)(nil), (*io.ReadWriteCloser)(nil), (*fmt.Stringer)(nil),
	sync.Mutex{}, &sync.Mutex{}, isync.Mutex{}, &isync.Mutex{}, &sync.WaitGroup{},
	bytes.Buffer{}, &strings.Reader{}, url.URL{}, url.Values{}, time.Time{},
	map[Item][]*Node{}, []map[string]Handler{}, [2]chan<- Event{},
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "dump" {
		dump()
		return
	}
	var h Handler = &echo{prefix: []byte("> ")}
	out, _ := h.Handle([]byte("hi"))
	var c Closer = &echo{}
	c.flush(true)
	d := &Derived{Mutex: &isync.Mutex{}, Reader: strings.NewReader("x")}
	d.Lock()
	d.SetName("n")
	fmt.Println(string(out), d.Name(), Headers{"a": {"b"}}.Get("a"), len(roots))
}

type fieldRecord struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	TypePkg  string  `json:"type_pkg"`
	Offset   uintptr `json:"offset"`
	Embedded bool    `json:"embedded"`
	Tag      string  `json:"tag"`
}

type methodRecord struct {
	Name string `json:"name"`
	Sig  string `json:"sig"`
}

type typeRecord struct {
	String     string         `json:"string"`
	PkgPath    string         `json:"pkg_path"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Size       uintptr        `json:"size"`
	Align      int            `json:"align"`
	FieldAlign int            `json:"field_align"`
	Fields     []fieldRecord  `json:"fields"`
	IMethods   []methodRecord `json:"imethods"`
	Methods    []methodRecord `json:"methods"`
}

// signature writes a func type's parameters and results the way its
// reflect.Type.String() does, without the `func` keyword, skipping the first
// `skip` parameters (a method value's receiver).
func signature(t reflect.Type, skip int) string {
	var b bytes.Buffer
	b.WriteString("(")
	for i := skip; i < t.NumIn(); i++ {
		if i > skip {
			b.WriteString(", ")
		}
		if t.IsVariadic() && i == t.NumIn()-1 {
			b.WriteString("..." + t.In(i).Elem().String())
		} else {
			b.WriteString(t.In(i).String())
		}
	}
	b.WriteString(")")
	switch t.NumOut() {
	case 0:
	case 1:
		b.WriteString(" " + t.Out(0).String())
	default:
		b.WriteString(" (")
		for i := 0; i < t.NumOut(); i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(t.Out(i).String())
		}
		b.WriteString(")")
	}
	return b.String()
}

func dump() {
	seen := map[reflect.Type]bool{}
	var queue []reflect.Type
	push := func(t reflect.Type) {
		if !seen[t] {
			seen[t] = true
			queue = append(queue, t)
		}
	}
	for _, r := range roots {
		t := reflect.TypeOf(r)
		push(t)
		if t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Interface {
			push(t.Elem())
		}
	}
	enc := json.NewEncoder(os.Stdout)
	for len(queue) > 0 {
		t := queue[0]
		queue = queue[1:]
		rec := typeRecord{
			String:     t.String(),
			PkgPath:    t.PkgPath(),
			Name:       t.Name(),
			Kind:       t.Kind().String(),
			Size:       t.Size(),
			Align:      t.Align(),
			FieldAlign: t.FieldAlign(),
		}
		switch t.Kind() {
		case reflect.Array, reflect.Chan, reflect.Ptr, reflect.Slice:
			push(t.Elem())
		case reflect.Map:
			push(t.Key())
			push(t.Elem())
		case reflect.Func:
			for i := 0; i < t.NumIn(); i++ {
				push(t.In(i))
			}
			for i := 0; i < t.NumOut(); i++ {
				push(t.Out(i))
			}
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				push(f.Type)
				rec.Fields = append(rec.Fields, fieldRecord{
					Name:     f.Name,
					Type:     f.Type.String(),
					TypePkg:  f.Type.PkgPath(),
					Offset:   f.Offset,
					Embedded: f.Anonymous,
					Tag:      string(f.Tag),
				})
			}
		case reflect.Interface:
			for i := 0; i < t.NumMethod(); i++ {
				m := t.Method(i)
				push(m.Type)
				rec.IMethods = append(rec.IMethods, methodRecord{Name: m.Name, Sig: signature(m.Type, 0)})
			}
		}
		if t.Kind() != reflect.Interface {
			for i := 0; i < t.NumMethod(); i++ {
				m := t.Method(i)
				rec.Methods = append(rec.Methods, methodRecord{Name: m.Name, Sig: signature(m.Type, 1)})
			}
		}
		enc.Encode(rec)
	}
}
