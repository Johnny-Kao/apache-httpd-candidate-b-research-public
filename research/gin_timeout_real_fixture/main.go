package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
)

// This uses the actual published gin-contrib/timeout v0.0.1 implementation.
// That version runs the handler in a goroutine and, on timeout, writes the
// timeout response through the original gin ResponseWriter without stopping
// the handler goroutine.
func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: fixture PORT")
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.GET("/tenant-a/slow", timeout.New(
		timeout.WithTimeout(20*time.Millisecond),
		timeout.WithHandler(func(c *gin.Context) {
			delay := 120 * time.Millisecond
			if raw := c.Query("delay_ms"); raw != "" {
				if value, parseErr := strconv.Atoi(raw); parseErr == nil && value > 0 && value < 2000 {
					delay = time.Duration(value) * time.Millisecond
				}
			}
			time.Sleep(delay)
			// The attacker controls only this marker through ordinary input.
			c.String(200, "ATTACKER-LATE:"+c.Query("marker"))
		}),
	))
	r.GET("/tenant-b/victim", func(c *gin.Context) {
		c.String(200, "VICTIM-OWN")
	})

	log.Printf("gin_timeout_real_fixture_listening=%d", port)
	log.Fatal(r.Run(fmt.Sprintf("127.0.0.1:%d", port)))
}
