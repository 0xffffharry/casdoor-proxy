package cache

import (
	"github.com/gomodule/redigo/redis"
	"time"
)

type RedisCache struct {
	redisPool *redis.Pool
}

func NewRedisCache(redisPool *redis.Pool) *RedisCache {
	return &RedisCache{
		redisPool: redisPool,
	}
}

func (rc *RedisCache) Set(key string, value string, deadline time.Time) error {
	conn := rc.redisPool.Get()
	defer conn.Close()

	_, err := conn.Do("SETEX", key, int(deadline.Sub(time.Now()).Seconds()), value)
	return err
}

func (rc *RedisCache) Get(key string) (string, time.Time, error) {
	conn := rc.redisPool.Get()
	defer conn.Close()

	value, err := redis.Bytes(conn.Do("GET", key))
	if err != nil {
		return "", time.Time{}, err
	}

	ttl, err := redis.Int(conn.Do("TTL", key))
	if err != nil {
		return "", time.Time{}, err
	}

	return string(value), time.Now().Add(time.Duration(ttl) * time.Second), nil
}

func (rc *RedisCache) GetAndDel(key string) (string, time.Time, error) {
	conn := rc.redisPool.Get()
	defer conn.Close()

	value, err := redis.Bytes(conn.Do("GET", key))
	if err != nil {
		return "", time.Time{}, err
	}

	ttl, err := redis.Int(conn.Do("TTL", key))
	if err != nil {
		return "", time.Time{}, err
	}

	_, err = conn.Do("DEL", key)
	if err != nil {
		return "", time.Time{}, err
	}

	return string(value), time.Now().Add(time.Duration(ttl) * time.Second), nil
}
