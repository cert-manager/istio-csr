package healthz

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"
)

// Healthz is used to maintain and expose a readiness probe
type Healthz struct {
	log *logrus.Entry

	mu       sync.RWMutex
	listener net.Listener

	addr, path string
	checks     []*Check
}

// Check holds a single check of a readiness probe
type Check struct {
	b bool
}

func New(log *logrus.Entry, port int, path string) *Healthz {
	portS := strconv.Itoa(port)
	log = log.WithField("module", "readiness-probe").
		WithField("port", portS).
		WithField("path", path)

	return &Healthz{
		log:  log,
		addr: fmt.Sprintf("0.0.0.0:%d", port),
		path: path,
	}
}

func (h *Healthz) Start(ctx context.Context) error {
	h.log.Info("starting readiness probe server")
	mux := http.NewServeMux()
	mux.HandleFunc(h.path, h.handle)

	l, err := net.Listen("tcp", h.addr)
	if err != nil {
		return fmt.Errorf("failed to create heatlhz listener: %s", err)
	}
	h.listener = l

	go func() {
		if err := http.Serve(l, mux); err != nil {
			h.log.Errorf("failed to serve: %s", err)
		}
	}()

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	return nil
}

func (h *Healthz) Register() *Check {
	h.mu.Lock()
	defer h.mu.Unlock()

	check := new(Check)
	h.checks = append(h.checks, check)

	return check
}

func (h *Healthz) servingPort() (string, error) {
	_, port, err := net.SplitHostPort(h.listener.Addr().String())
	if err != nil {
		return "", err
	}

	return port, nil
}

func (h *Healthz) handle(rw http.ResponseWriter, _ *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.checks) == 0 {
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(rw, "not ok")
		return
	}

	for _, check := range h.checks {
		if !check.b {
			rw.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(rw, "not ok")
			return
		}
	}

	rw.WriteHeader(http.StatusOK)
	fmt.Fprint(rw, "ok")
}

func (c *Check) Set(ready bool) {
	c.b = ready
}
