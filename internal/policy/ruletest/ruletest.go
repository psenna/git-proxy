// Package ruletest provides table-driven test helpers for policy Rules.
//
// A rule's unit tests build a one-rule Engine via NewEngine and assert the
// verdict for each case. These helpers remove the boilerplate so a rule test
// file reads as a table of (input, expected verdict).
package ruletest

import (
	"testing"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
)

// PushCase is one row of a push-rule test table.
type PushCase struct {
	// Name identifies the row in test output.
	Name string
	// Req is the push request fed to the rule.
	Req port.PushRequest
	// Want is the expected verdict. Reasons are not compared row-by-row; use
	// WantReason to assert the (single) denial reason's message.
	Want port.Verdict
	// WantReason, when non-empty, asserts the first denial reason's message.
	WantReason string
}

// FetchCase is one row of a fetch-rule test table.
type FetchCase struct {
	Name       string
	Req        port.FetchRequest
	Want       port.Verdict
	WantReason string
}

// RunPush runs a table of push cases against rule under a FirstDeny engine.
// Each case is evaluated in isolation with a fresh one-rule engine. The rule
// is exercised directly; no registry or config is involved.
func RunPush(t *testing.T, rule port.Rule, cases []PushCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			e := policy.NewEngine(policy.FirstDeny, rule)
			got := e.EvaluatePush(c.Req)
			if got.Verdict != c.Want {
				t.Fatalf("verdict = %v, want %v (reasons: %+v)", got.Verdict, c.Want, got.Reasons)
			}
			if c.WantReason != "" {
				if len(got.Reasons) == 0 || got.Reasons[0].Message != c.WantReason {
					t.Fatalf("reason = %+v, want first message %q", got.Reasons, c.WantReason)
				}
			}
		})
	}
}

// RunFetch runs a table of fetch cases against rule under a FirstDeny engine.
func RunFetch(t *testing.T, rule port.Rule, cases []FetchCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			e := policy.NewEngine(policy.FirstDeny, rule)
			got := e.EvaluateFetch(c.Req)
			if got.Verdict != c.Want {
				t.Fatalf("verdict = %v, want %v (reasons: %+v)", got.Verdict, c.Want, got.Reasons)
			}
			if c.WantReason != "" {
				if len(got.Reasons) == 0 || got.Reasons[0].Message != c.WantReason {
					t.Fatalf("reason = %+v, want first message %q", got.Reasons, c.WantReason)
				}
			}
		})
	}
}