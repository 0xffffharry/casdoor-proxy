package cache

import "time"

type Cache interface {
	Set(key string, value string, deadline time.Time) error
	Get(key string) (string, time.Time, error)
	GetAndDel(key string) (string, time.Time, error)
}
