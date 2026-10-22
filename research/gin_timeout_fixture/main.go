package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
)

// This uses the published v0.0.1 gin-contrib/timeout middleware. That version
// runs the handler in a goroutine and returns a timeout response without
// stopping the handler goroutine. The late write is therefore caused by an
// ordinary application request, not by a backend test double choosing to emit
// bytes on the wire.
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

	// The attacker controls only the marker and delay query parameters. The
	// timeout response is sent first; the handler then writes the marker later.
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
			_, _ = c.Writer.WriteString("ATTACKER-LATE:" + c.Query("marker"))
		}),
		timeout.WithResponse(func(c *gin.Context) {
			c.String(http.StatusRequestTimeout, "TIMEOUT-A")
		}),
	))

	r.GET("/tenant-b/victim", func(c *gin.Context) {
		c.String(http.StatusOK, "VICTIM-OWN")
	})

	log.Printf("gin_timeout_fixture_listening=%d", port)
	log.Fatal(r.Run(fmt.Sprintf("127.0.0.1:%d", port)))
}
