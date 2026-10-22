package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// This is a source-equivalent reproduction of the published
// gin-contrib/timeout v0.0.1 control flow. That version runs the handler in a
// goroutine and returns a timeout response without stopping the handler
// goroutine. Keeping the fixture on net/http avoids pulling the old Gin
// dependency graph into CI while preserving the response-writer lifetime bug.
func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: fixture PORT")
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// The attacker controls only the marker and delay query parameters. The
	// timeout response is sent first; the handler then writes the marker later.
	mux := http.NewServeMux()
	mux.HandleFunc("/tenant-a/slow", timeoutMiddleware(20*time.Millisecond,
		func(w http.ResponseWriter, r *http.Request) {
			delay := 120 * time.Millisecond
			if raw := r.URL.Query().Get("delay_ms"); raw != "" {
				if value, parseErr := strconv.Atoi(raw); parseErr == nil && value > 0 && value < 2000 {
					delay = time.Duration(value) * time.Millisecond
				}
			}
			time.Sleep(delay)
			_, _ = fmt.Fprint(w, "ATTACKER-LATE:"+r.URL.Query().Get("marker"))
		},
	))

	mux.HandleFunc("/tenant-b/victim", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "VICTIM-OWN")
	})

	log.Printf("gin_timeout_fixture_listening=%d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), mux))
}

func timeoutMiddleware(timeout time.Duration, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		finished := make(chan struct{}, 1)
		go func() {
			handler(w, r)
			finished <- struct{}{}
		}()
		select {
		case <-finished:
		case <-time.After(timeout):
			w.WriteHeader(http.StatusRequestTimeout)
			_, _ = fmt.Fprint(w, "TIMEOUT-A")
		}
	}
}
