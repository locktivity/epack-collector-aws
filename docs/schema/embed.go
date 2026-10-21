// Package schema embeds the JSON Schema of the collector's detailed artifact
// and its trace map, so the collector can check its output against the schema
// when it emits.
package schema

import _ "embed"

// V1 is the JSON Schema of the detailed artifact, artifacts/aws.json.
//
//go:embed v1.0.0.json
var V1 []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte
