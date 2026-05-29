// A deliberately complex Go program exercising the shapes unstrip needs to
// handle on real binaries: generics, deep interface chains, embedded structs,
// reflection, goroutines, channels, large dep trees, init-time work.
//
// Built as a single static binary, this exercises pclntab walking, every
// type kind, dense itablinks, and the full buildinfo blob.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/spf13/cobra"
)

// ----- generics -----

type Number interface {
	~int | ~int64 | ~float64
}

type Set[T comparable] struct {
	items map[T]struct{}
	mu    sync.RWMutex
}

func NewSet[T comparable]() *Set[T] {
	return &Set[T]{items: make(map[T]struct{})}
}

func (s *Set[T]) Add(v T)          { s.mu.Lock(); s.items[v] = struct{}{}; s.mu.Unlock() }
func (s *Set[T]) Has(v T) bool     { s.mu.RLock(); _, ok := s.items[v]; s.mu.RUnlock(); return ok }
func (s *Set[T]) Len() int         { s.mu.RLock(); defer s.mu.RUnlock(); return len(s.items) }

func Sum[T Number](xs []T) T {
	var acc T
	for _, x := range xs {
		acc += x
	}
	return acc
}

// ----- interface chains -----

type Reader interface{ Read(p []byte) (int, error) }
type Writer interface{ Write(p []byte) (int, error) }
type Closer interface{ Close() error }

type ReadWriteCloser interface {
	Reader
	Writer
	Closer
}

type RingBuffer struct {
	buf    []byte
	r, w   int
	closed bool
}

func (rb *RingBuffer) Read(p []byte) (int, error) {
	if rb.closed && rb.r == rb.w {
		return 0, io.EOF
	}
	n := copy(p, rb.buf[rb.r:])
	rb.r += n
	return n, nil
}

func (rb *RingBuffer) Write(p []byte) (int, error) {
	rb.buf = append(rb.buf, p...)
	rb.w += len(p)
	return len(p), nil
}

func (rb *RingBuffer) Close() error { rb.closed = true; return nil }

// ----- embedded structs -----

type Metadata struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	Tags      map[string]string
}

type Resource struct {
	ID   string
	Kind string
	Metadata
}

type Deployment struct {
	Resource
	Replicas int32
	Image    string
	Env      []EnvVar
}

type EnvVar struct {
	Name  string
	Value string
}

// ----- reflection-using helpers -----

func fieldNames(v interface{}) []string {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil
	}
	out := make([]string, 0, rv.NumField())
	for i := 0; i < rv.NumField(); i++ {
		out = append(out, rv.Type().Field(i).Name)
	}
	sort.Strings(out)
	return out
}

// ----- goroutine pipeline -----

type Job struct {
	ID      int
	Payload []byte
	Result  chan error
}

func worker(ctx context.Context, id int, jobs <-chan Job) {
	for {
		select {
		case <-ctx.Done():
			return
		case j, ok := <-jobs:
			if !ok {
				return
			}
			j.Result <- fmt.Errorf("worker %d processed job %d (%d bytes)", id, j.ID, len(j.Payload))
		}
	}
}

func runPipeline(ctx context.Context, n int) error {
	jobs := make(chan Job, n)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) { defer wg.Done(); worker(ctx, id, jobs) }(i)
	}
	for i := 0; i < n; i++ {
		jobs <- Job{ID: i, Payload: []byte(strings.Repeat("x", 16)), Result: make(chan error, 1)}
	}
	close(jobs)
	wg.Wait()
	return nil
}

// ----- aws sdk surface -----

func describeBuckets() []types.Bucket {
	return []types.Bucket{
		{Name: aws.String("logs"), CreationDate: aws.Time(time.Now())},
		{Name: aws.String("backups"), CreationDate: aws.Time(time.Now())},
	}
}

// ----- main -----

func main() {
	root := &cobra.Command{Use: "complex"}

	root.AddCommand(&cobra.Command{
		Use:   "set",
		Short: "exercise generics",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := NewSet[string]()
			for _, a := range args {
				s.Add(a)
			}
			fmt.Println("len:", s.Len(), "sum:", Sum([]int{1, 2, 3, 4, 5}))
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "pipeline",
		Short: "exercise goroutines",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			return runPipeline(ctx, 20)
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "describe",
		Short: "exercise reflection + embedded structs",
		RunE: func(cmd *cobra.Command, args []string) error {
			d := Deployment{Resource: Resource{ID: "1", Kind: "deploy"}, Replicas: 3, Image: "img"}
			fmt.Println("fields:", fieldNames(d))
			b, _ := json.Marshal(d)
			os.Stdout.Write(b)
			fmt.Println()
			fmt.Println("buckets:", len(describeBuckets()))

			var rwc ReadWriteCloser = &RingBuffer{buf: make([]byte, 0, 1024)}
			rwc.Write([]byte("hello"))
			out := make([]byte, 16)
			n, _ := rwc.Read(out)
			fmt.Println("read", n, "bytes:", string(out[:n]))
			rwc.Close()
			return nil
		},
	})

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
