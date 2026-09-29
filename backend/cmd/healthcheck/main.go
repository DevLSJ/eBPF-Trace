// Command healthcheck is the container HEALTHCHECK for the distroless backend
// image (no shell or curl there). It GETs /health on the local port and exits
// non-zero unless the backend answers 200.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("BACKEND_PORT")
	if port == "" {
		port = "8000"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		os.Exit(1)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", res.Status)
		os.Exit(1)
	}
}
