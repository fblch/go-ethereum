// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// ADDED by Jakub Pajek (size constrained snapshot cache)
package lru

import (
	"sync"
)

// SizeType is the type constraint for values stored in SizeCountConstrainedCache.
type SizeType interface {
	Size() int
}

// SizeCountConstrainedCache is a cache where capacity is in bytes and item count. When the cache
// is at capacity (either the size or the item count is exceeded), and a new item is added, older
// items are evicted until both the size and the item count constraint is met.
//
// OBS: This cache assumes that items are content-addressed: keys are unique per content.
// In other words: two Add(..) with the same key K, will always have the same value V.
type SizeCountConstrainedCache[K comparable, V SizeType] struct {
	size     uint64
	maxSize  uint64
	maxCount int
	lru      BasicLRU[K, V]
	lock     sync.Mutex
}

// NewSizeCountConstrainedCache creates a new size and item count constrained LRU cache.
func NewSizeCountConstrainedCache[K comparable, V SizeType](maxSize uint64, maxCount int) *SizeCountConstrainedCache[K, V] {
	if maxCount <= 0 {
		maxCount = 1
	}
	return &SizeCountConstrainedCache[K, V]{
		size:     0,
		maxSize:  maxSize,
		maxCount: maxCount,
		lru:      NewBasicLRU[K, V](maxCount),
	}
}

// Add adds a value to the cache. Returns true if an eviction occurred.
// OBS: This cache assumes that items are content-addressed: keys are unique per content.
// In other words: two Add(..) with the same key K, will always have the same value V.
// OBS: The value is _not_ copied on Add, so the caller must not modify it afterwards.
func (c *SizeCountConstrainedCache[K, V]) Add(key K, value V) (evicted bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Unless it is already present, might need to evict something.
	// OBS: If it is present, we still call Add internally to bump the recentness.
	present := c.lru.Contains(key)
	if c.lru.Len() >= c.maxCount && !present {
		_, v, _ := c.lru.RemoveOldest()
		c.size -= uint64(v.Size())
		evicted = true
	}
	if !present {
		targetSize := c.size + uint64(value.Size())
		for targetSize > c.maxSize {
			evicted = true
			_, v, ok := c.lru.RemoveOldest()
			if !ok {
				// list is now empty. Break
				break
			}
			targetSize -= uint64(v.Size())
		}
		c.size = targetSize
	}
	c.lru.Add(key, value)
	return evicted
}

// Get looks up a key's value from the cache.
func (c *SizeCountConstrainedCache[K, V]) Get(key K) (V, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.lru.Get(key)
}

// Len returns the current number of items in the cache.
func (c *SizeCountConstrainedCache[K, V]) Len() int {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.lru.Len()
}

// Size returns the total size of items in the cache.
func (c *SizeCountConstrainedCache[K, V]) Size() uint64 {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.size
}
