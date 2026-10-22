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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/delay" {
			time.Sleep(250 * time.Millisecond)
			tag := r.URL.Query().Get("tag")
			w.Header().Set("X-Attacker-Tag", tag)
			fmt.Fprintf(w, "ATTACKER-%s", tag)
			return
		}
		if r.URL.Path == "/victim" {
			fmt.Fprint(w, "VICTIM-OWN")
			return
		}
		http.NotFound(w, r)
	})
	log.Printf("go_connect_fixture_listening=%s", os.Args[1])
	log.Fatal(http.ListenAndServe("127.0.0.1:"+os.Args[1], mux))
}
