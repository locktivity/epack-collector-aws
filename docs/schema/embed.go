// Package schema embeds the JSON Schema of the collector's detailed artifact
// and its trace map, so the collector can check its output against the schema
// when it emits. It also embeds the methods the collector gives for the
// access-posture and vuln-scanning artifacts.
package schema

import (
	_ "embed"
	"encoding/json"
)

// V1 is the JSON Schema of the detailed artifact, artifacts/aws.details.json.
//
//go:embed v1.0.0.json
var V1 []byte

// methods is methods.json. It holds one plain sentence on how the collector
// measures each field of the evidencepack/access-posture@v1 and
// evidencepack/vuln-scanning@v1 artifacts.
//
//go:embed methods.json
var methods []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Methods returns the sentences in methods.json for
// componentsdk.CollectorSpec.Methods, keyed by schema ID. The SDK writes each
// one as the x-epack-method of its field in the SDK's own schema for the type.
func Methods() map[string]map[string]string {
	var bySchema map[string]map[string]string
	if err := json.Unmarshal(methods, &bySchema); err != nil {
		panic("docs/schema/methods.json: " + err.Error())
	}
	return bySchema
}
