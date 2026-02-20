package pool

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/rs/zerolog"
)

// SyncJob is a unit of work for the worker pool.
type SyncJob struct {
	Action          string // "ban" or "delete"
	IP              string
	IPv6            bool
	Site            string
	ExpiresAt       time.Time
	Retries         int
	Origin          string // CrowdSec decision origin (e.g. "CAPI", "crowdsec")
	RemediationType string // CrowdSec remediation type (e.g. "ban")
}

// JobHandler processes a single SyncJob. Returns an error if the job should be retried.
type JobHandler func(ctx context.Context, job SyncJob) error

// Config holds worker pool configuration.
type Config struct {
	Workers    int
	QueueDepth int
	MaxRetries int
	RetryBase  time.Duration
}

// Pool is a configurable worker pool with bounded retry logic.
type Pool struct {
	cfg      Config
	jobs     chan SyncJob
	handler  JobHandler
	log      zerolog.Logger
	wg       sync.WaitGroup
	stopOnce sync.Once
}

// New creates a Pool with the given config and handler.
func New(cfg Config, handler JobHandler, log zerolog.Logger) (*Pool, error) {
	if cfg.Workers < 1 || cfg.Workers > 64 {
		return nil, fmt.Errorf("POOL_WORKERS must be 1–64, got %d", cfg.Workers)
	}
	if cfg.QueueDepth < 1 {
		cfg.QueueDepth = 4096
	}
	if cfg.RetryBase == 0 {
		cfg.RetryBase = time.Second
	}
	return &Pool{
		cfg:     cfg,
		jobs:    make(chan SyncJob, cfg.QueueDepth),
		handler: handler,
		log:     log,
	}, nil
}

// Start launches the worker goroutines. ctx controls worker lifetime.
func (p *Pool) Start(ctx context.Context) {
	for i := 0; i < p.cfg.Workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}
}

// Enqueue attempts a non-blocking send. Returns false if the buffer is full.
func (p *Pool) Enqueue(job SyncJob) bool {
	select {
	case p.jobs <- job:
		metrics.JobsEnqueued.WithLabelValues(job.Action).Inc()
		return true
	default:
		metrics.JobsDropped.WithLabelValues("buffer_full").Inc()
		p.log.Warn().Str("ip", job.IP).Str("action", job.Action).Msg("job dropped: queue full")
		return false
	}
}

// Stop closes the job channel and waits for all workers to drain.
// Safe to call only once.
func (p *Pool) Stop() {
	p.stopOnce.Do(func() {
		close(p.jobs)
	})
	p.wg.Wait()
}

// Depth returns the current number of pending jobs.
func (p *Pool) Depth() int {
	return len(p.jobs)
}

// worker dequeues jobs and processes them with inline retry (no re-enqueue).
// Inline retry avoids the channel close/send race condition.
func (p *Pool) worker(ctx context.Context, id int) {
	defer p.wg.Done()
	log := p.log.With().Int("worker_id", id).Logger()

	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-p.jobs:
			if !ok {
				return // channel closed by Stop()
			}
			metrics.WorkerQueueDepth.Set(float64(len(p.jobs)))
			p.processWithRetry(ctx, job, log)
		}
	}
}

// processWithRetry runs the handler inline with exponential backoff.
// This avoids sending to a closed jobs channel (no re-enqueue).
func (p *Pool) processWithRetry(ctx context.Context, job SyncJob, log zerolog.Logger) {
	for attempt := 0; attempt <= p.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := p.backoff(attempt - 1)
			log.Warn().Str("ip", job.IP).Int("attempt", attempt).
				Dur("backoff", backoff).Msg("retrying job")
			select {
			case <-ctx.Done():
				metrics.JobsProcessed.WithLabelValues(job.Action, "error").Inc()
				return
			case <-time.After(backoff):
			}
		}

		if err := p.handler(ctx, job); err != nil {
			if attempt < p.cfg.MaxRetries {
				metrics.JobsProcessed.WithLabelValues(job.Action, "retried").Inc()
				continue
			}
			metrics.JobsProcessed.WithLabelValues(job.Action, "error").Inc()
			log.Error().Err(err).Str("ip", job.IP).
				Int("max_retries", p.cfg.MaxRetries).Msg("job failed: max retries exceeded")
			return
		}

		metrics.JobsProcessed.WithLabelValues(job.Action, "success").Inc()
		return
	}
}

// backoff computes exponential backoff with a max cap.
func (p *Pool) backoff(retries int) time.Duration {
	multiplier := math.Pow(2, float64(retries))
	d := time.Duration(float64(p.cfg.RetryBase) * multiplier)
	if max := 5 * time.Minute; d > max {
		d = max
	}
	return d
}
