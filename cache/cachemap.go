package cache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type CacheMap struct {
	m      map[string]*item
	lock   sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

type item struct {
	key      string
	value    string
	deadline time.Time
}

func NewCacheMap(ctx context.Context) *CacheMap {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	cm := &CacheMap{
		m:      make(map[string]*item),
		ctx:    ctx,
		cancel: cancel,
	}
	go cm.autoDelete()
	return cm
}

func (cm *CacheMap) autoDelete() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cm.lock.Lock()
			for _, i := range cm.m {
				if !i.deadline.IsZero() && i.deadline.Before(time.Now()) {
					delete(cm.m, i.key)
				}
			}
			cm.lock.Unlock()
		case <-cm.ctx.Done():
			return
		}
	}
}

func (cm *CacheMap) Set(key string, value string, deadline time.Time) error {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	i, ok := cm.m[key]
	if !ok {
		i = &item{
			key:      key,
			value:    value,
			deadline: deadline,
		}
	} else {
		if value != i.value {
			i.value = value
		}
		if deadline != i.deadline {
			i.deadline = deadline
		}
	}

	return nil
}

func (cm *CacheMap) Get(key string) (string, time.Time, error) {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	i, ok := cm.m[key]
	if !ok {
		return "", time.Time{}, fmt.Errorf("key %s not found", key)
	}
	return i.value, i.deadline, nil
}

func (cm *CacheMap) GetAndDel(key string) (string, time.Time, error) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	i, ok := cm.m[key]
	if !ok {
		return "", time.Time{}, fmt.Errorf("key %s not found", key)
	}
	delete(cm.m, key)
	return i.value, i.deadline, nil
}
