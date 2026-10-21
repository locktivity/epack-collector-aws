package collector

import (
	"context"
	"sync"

	"github.com/locktivity/epack/componentsdk"
)

// stepper runs the parts of an account's collection one after another as
// the run's steps, each ending when the next one starts.
type stepper struct {
	ctx     context.Context
	current *componentsdk.Step
}

// next ends the current step and starts the one named name, returning the
// context the step's calls are made with.
func (s *stepper) next(name, title string) context.Context {
	s.end()
	ctx, step := componentsdk.StartStep(s.ctx, name, title)
	s.current = step
	return ctx
}

// end ends the current step, if there is one.
func (s *stepper) end() {
	s.current.End()
	s.current = nil
}

// regionalSteps are the steps of the surfaces every region scans. Regions
// scan concurrently, so a surface's step starts when the first region starts
// the surface and ends when the last one finishes it.
type regionalSteps struct {
	ctx     context.Context
	regions int
	global  map[string]bool

	mu    sync.Mutex
	steps map[string]*regionalStep
}

type regionalStep struct {
	ctx  context.Context
	step *componentsdk.Step
	left int
}

// newRegionalSteps returns the steps of a scan of regions regions. Each
// surface in global also makes one account-wide pass after the regions, and
// that pass belongs to the surface's step too.
func newRegionalSteps(ctx context.Context, regions int, global ...string) *regionalSteps {
	s := &regionalSteps{ctx: ctx, regions: regions, global: map[string]bool{}, steps: map[string]*regionalStep{}}
	for _, name := range global {
		s.global[name] = true
	}
	return s
}

// enter returns the context one region's calls for the surface named name
// are made with, starting the surface's step if no region has yet.
func (s *regionalSteps) enter(name, title string) context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.steps[name]
	if !ok {
		left := s.regions
		if s.global[name] {
			left++
		}
		ctx, step := componentsdk.StartStep(s.ctx, name, title)
		st = &regionalStep{ctx: ctx, step: step, left: left}
		s.steps[name] = st
	}
	return st.ctx
}

// leave records that one region, or the account-wide pass, finished the
// surface named name, and ends its step when it was the last.
func (s *regionalSteps) leave(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.steps[name]
	st.left--
	if st.left == 0 {
		st.step.End()
	}
}
