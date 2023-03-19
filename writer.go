package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// loggingWriter keeps track of a HTTP response, registering in a prometheus metric
// when the header is written.
type loggingWriter struct {
	W     http.ResponseWriter // Calls are forwarded.
	Start time.Time
	R     *http.Request

	Op string // Set by router.

	// Set by handlers.
	StatusCode int
	Size       int64
	WriteErr   error
}

func (w *loggingWriter) Header() http.Header {
	return w.W.Header()
}

func (w *loggingWriter) setStatusCode(statusCode int) {
	if w.StatusCode != 0 {
		return
	}

	if debugFlag {
		log.Printf("http response %s %s: %d", w.R.Method, w.Op, statusCode)
	}

	method := strings.ToLower(w.R.Method)
	switch method {
	case "head", "get", "post", "put", "patch", "delete":
	default:
		method = "(other)"
	}
	w.StatusCode = statusCode
	metricRequest.WithLabelValues(method, w.Op, fmt.Sprintf("%d", w.StatusCode)).Observe(float64(time.Since(w.Start)) / float64(time.Second))
}

func (w *loggingWriter) Write(buf []byte) (int, error) {
	if w.Size == 0 {
		w.setStatusCode(http.StatusOK)
	}

	n, err := w.W.Write(buf)
	if n > 0 {
		w.Size += int64(n)
	}
	if err != nil && w.WriteErr == nil {
		w.WriteErr = err
	}
	return n, err
}

func (w *loggingWriter) WriteHeader(statusCode int) {
	w.setStatusCode(statusCode)
	w.W.WriteHeader(statusCode)
}
