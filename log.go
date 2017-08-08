// Lightly modified from Mint

package minq

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// We use this environment variable to control logging.  It should be a
// comma-separated list of log tags (see below) or "*" to enable all logging.
const logConfigVar = "MINQ_LOG"

// Pre-defined log types
const (
	logTypeAead       = "aead"
	logTypeCodec      = "codec"
	logTypeConnBuffer = "connbuffer"
	logTypeConnection = "connection"
	logTypeAck        = "ack"
	logTypeFrame      = "frame"
	logTypeHandshake  = "handshake"
	logTypeTls        = "tls"
	logTypeTrace      = "trace"
	logTypeServer     = "server"
	logTypeUdp        = "udp"
)

var (
	logFunction = log.Printf
	logAll      = true
	logSettings = map[string]bool{}
)

func init() {
	parseLogEnv(os.Environ())
}

func parseLogEnv(env []string) {
	for _, stmt := range env {
		if strings.HasPrefix(stmt, logConfigVar+"=") {
			val := stmt[len(logConfigVar)+1:]

			if val == "*" {
				logAll = true
			} else {
				for _, t := range strings.Split(val, ",") {
					logSettings[t] = true
				}
			}
		}
	}
}

func logf(tag string, format string, args ...interface{}) {
	if logAll || logSettings[tag] {
		fullFormat := fmt.Sprintf("[%s] %s", tag, format)
		logFunction(fullFormat, args...)
	}
}
