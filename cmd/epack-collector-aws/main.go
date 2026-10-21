// epack-collector-aws collects AWS account security posture.
//
// This binary is designed to be executed by the epack collector runner.
// It uses the epack Component SDK for protocol compliance.
package main

import (
	"github.com/locktivity/epack-collector-aws/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

// Build-time variables set via -ldflags
var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(collector.Spec(Version, Commit), collector.Run)
}
