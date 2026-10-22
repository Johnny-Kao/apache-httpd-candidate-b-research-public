package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: fixture PORT")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/late", func(w http.ResponseWriter, r *http.Request) {
		go func(writer http.ResponseWriter) {
			time.Sleep(100 * time.Millisecond)
			_, _ = fmt.Fprint(writer, "ATTACKER-LATE")
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
		}(w)
	})
	mux.HandleFunc("/victim", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		fmt.Fprint(w, "VICTIM-OWN")
	})
	log.Printf("go_late_write_fixture_listening=%s", os.Args[1])
	log.Fatal(http.ListenAndServe("127.0.0.1:"+os.Args[1], mux))
}
