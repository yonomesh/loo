package main

import (
	"os"

	"github.com/AdguardTeam/golibs/log"
)

var VersionString = ""

func main() {
	enableJsonOutput := os.Getenv("JSON") == "1"
	_ = enableJsonOutput
	skipTLSCertVerify := os.Getenv("VERIFY") == "0"
	_ = skipTLSCertVerify
	timeoutStr := os.Getenv("TIMEOUT")
	_ = timeoutStr
	enableHTTP3 := os.Getenv("HTTP3") == "1"
	_ = enableHTTP3
	verbose := os.Getenv("VERBOSE") == "1"
	_ = verbose
	padding := os.Getenv("PAD") == "1"
	_ = padding

	if verbose {
		log.SetLevel(log.DEBUG)
	}

}
