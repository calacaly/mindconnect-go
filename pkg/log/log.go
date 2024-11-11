package log

import (
	"os"

	"github.com/charmbracelet/log"
)

var Logger log.Logger

func init() {
	Logger = *log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller: true,
		Level:        log.DebugLevel,
	})
}
