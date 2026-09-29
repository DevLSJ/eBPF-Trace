package store

import (
	"context"
	"encoding/json"

	"github.com/redis/go-redis/v9"

	"github.com/DevLSJ/ebpf-supplychain-guard/backend/internal/model"
)

const (
	recentKey     = "supplyguard:recent"
	verdictsTopic = "supplyguard:verdicts"
)

// Redis: 최근 판정 버퍼(LIST) + 위반 판정 Pub/Sub 발행
type Redis struct{ c *redis.Client }

func NewRedis(ctx context.Context, url string) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	c := redis.NewClient(opt)
	if err := c.Ping(ctx).Err(); err != nil {
		c.Close()
		return nil, err
	}
	return &Redis{c: c}, nil
}

func (r *Redis) Close() error { return r.c.Close() }

func (r *Redis) Ping(ctx context.Context) error { return r.c.Ping(ctx).Err() }

func (r *Redis) Push(ctx context.Context, v model.Verdict) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	pipe := r.c.Pipeline()
	pipe.LPush(ctx, recentKey, b)
	pipe.LTrim(ctx, recentKey, 0, RecentSize-1)
	if v.Matched {
		// 외부 알림 워커(Slack 등)가 구독할 수 있도록 위반만 발행
		pipe.Publish(ctx, verdictsTopic, b)
	}
	_, err = pipe.Exec(ctx)
	return err
}

// Recent: 최신순
func (r *Redis) Recent(ctx context.Context, n int) ([]model.Verdict, error) {
	if n <= 0 || n > RecentSize {
		n = RecentSize
	}
	raw, err := r.c.LRange(ctx, recentKey, 0, int64(n-1)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]model.Verdict, 0, len(raw))
	for _, s := range raw {
		var v model.Verdict
		if json.Unmarshal([]byte(s), &v) == nil {
			out = append(out, v)
		}
	}
	return out, nil
}
