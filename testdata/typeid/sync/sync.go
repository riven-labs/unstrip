// Package sync shares its name and its Mutex with the standard library, so a
// binary that links both has two types printed as sync.Mutex.
package sync

type Mutex struct {
	state int32
	owner *Mutex
}

func (m *Mutex) Lock()     { m.state++ }
func (m *Mutex) Unlock()   { m.state-- }
func (m Mutex) Held() bool { return m.state > 0 }
