package DNSContainer

import (
	"sync"
)

type Container struct {
	blockCapacity uint
	mutex         sync.Mutex
	entries       []*Entry
	blockToSend   [][]*Entry
}

func Create(blockCap uint) *Container {
	return &Container{blockCapacity: blockCap}
}

func (c *Container) Add(e *Entry) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.entries = append(c.entries, e)
}
