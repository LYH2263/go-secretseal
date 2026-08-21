package keyring

import (
	"errors"
	"time"
)

type Entry struct {
	ID        string
	Label     string
	Material  []byte
	Salt      []byte
	Meta      []string
	CreatedAt time.Time
	Revoked   bool
}

type Ring struct {
	byID   map[string]Entry
	active string
	order  []string
}

func New() *Ring {
	return &Ring{byID: map[string]Entry{}}
}

func (r *Ring) Add(e Entry) error {
	if _, ok := r.byID[e.ID]; ok {
		return errors.New("duplicate")
	}
	r.byID[e.ID] = e
	r.order = append(r.order, e.ID)
	return nil
}

func (r *Ring) Get(id string) (Entry, bool) {
	e, ok := r.byID[id]
	return e, ok
}

func (r *Ring) Put(e Entry) {
	r.byID[e.ID] = e
}

func (r *Ring) Remove(id string) error {
	if _, ok := r.byID[id]; !ok {
		return errors.New("missing")
	}
	delete(r.byID, id)
	out := r.order[:0]
	for _, x := range r.order {
		if x != id {
			out = append(out, x)
		}
	}
	r.order = out
	if r.active == id {
		r.active = ""
	}
	return nil
}

func (r *Ring) SetActive(id string) {
	r.active = id
}

func (r *Ring) ActiveID() string { return r.active }

func (r *Ring) Active() *Entry {
	if r.active == "" {
		return nil
	}
	e, ok := r.byID[r.active]
	if !ok {
		return nil
	}
	return &e
}

func (r *Ring) List() []Entry {
	out := make([]Entry, 0, len(r.order))
	for _, id := range r.order {
		if e, ok := r.byID[id]; ok {
			out = append(out, e)
		}
	}
	return out
}

func (r *Ring) Len() int { return len(r.byID) }
