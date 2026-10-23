package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// newTestCollector returns a collector with a gap log.
func newTestCollector(config Config) *Collector {
	c, err := New(config)
	if err != nil {
		panic(err)
	}
	return c
}

// pctIs reports whether p holds want.
func pctIs(p *int, want int) bool { return p != nil && *p == want }

// showPct prints a percentage pointer for a failure message.
func showPct(p *int) string {
	if p == nil {
		return "null"
	}
	return fmt.Sprint(*p)
}

// hasUnread reports whether u marks field unread with unmeasured items.
func hasUnread(u unread, field string, unmeasured int) bool {
	for _, f := range u.fields {
		if f.field == field {
			return f.unmeasured == unmeasured
		}
	}
	return false
}

// requireGap fails t unless a gap in the detailed artifact covers pointer.
func requireGap(t *testing.T, c *Collector, pointers ...string) {
	t.Helper()
	for _, pointer := range pointers {
		if !c.gaps.covered(pointer) {
			t.Errorf("no gap covers %s; gaps: %v", pointer, c.gaps.pointers(awsPath))
		}
	}
}

// requireNoGaps fails t if the detailed artifact has any gap.
func requireNoGaps(t *testing.T, c *Collector) {
	t.Helper()
	if got := c.gaps.pointers(awsPath); len(got) != 0 {
		t.Errorf("gaps = %v, want none", got)
	}
}

// runKit runs the collector in process against responses, as the kit's
// scenario runs do.
func runKit(t *testing.T, config map[string]any, secrets map[string]string, responses []collectortest.Response) componentsdk.InProcessResult {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	return componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    config,
		Secrets:   secrets,
		Transport: replay,
		Seed:      1,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		Clock:     func() time.Time { return kitClock },
	})
}

// gapAt returns the gap a run recorded at pointer in the artifact at path,
// or nil.
func gapAt(res componentsdk.InProcessResult, path, pointer string) *componentsdk.Gap {
	if res.Result == nil {
		return nil
	}
	for i, g := range res.Result.Gaps {
		if g.Path == path && g.Pointer == pointer {
			return &res.Result.Gaps[i]
		}
	}
	return nil
}

// decodeArtifact decodes the artifact a run emitted at path into v.
func decodeArtifact(t *testing.T, res componentsdk.InProcessResult, path string, v any) {
	t.Helper()
	for _, a := range res.Artifacts {
		if a.Path == path && a.File == "" {
			if err := json.Unmarshal(a.Data, v); err != nil {
				t.Fatalf("decoding %s: %v", path, err)
			}
			return
		}
	}
	t.Fatalf("no artifact at %s", path)
}
