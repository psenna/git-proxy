package rules

import (
	"fmt"

	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
	"github.com/psenna/git-proxy/internal/secret/regex"
)

const secretScanName = "secret_scan"

func init() {
	// Self-register so policy.Resolve can build the rule from config. The
	// factory builds a port.SecretScanner from the built-in defaults plus any
	// extra_patterns. A bad extra regex is surfaced as an evaluation error
	// (fail-closed) so a misconfigured pattern never silently disables
	// scanning. Default-on: enabled:true with no custom config scans with the
	// built-in defaults (this is a security rule). Disabling via enabled:false
	// is handled by Resolve (the rule is not built).
	policy.RegisterRule(secretScanName, func(cfg policy.RuleConfig) port.Rule {
		return newSecretScanRule(cfg)
	})
}

// newSecretScanRule builds a secret_scan rule from its RuleConfig. It is the
// package-internal constructor used by both the factory and the tests.
func newSecretScanRule(cfg policy.RuleConfig) port.Rule {
	r := &secretScanRule{}
	sc, err := regex.New(parseExtraPatterns(cfg.Params, "extra_patterns"))
	if err != nil {
		// Fail-closed: store the compile error and surface it from EvaluatePush
		// so the engine denies rather than silently scanning without the bad
		// pattern (or skipping scan entirely).
		r.compileErr = err
		return r
	}
	r.scanner = sc
	return r
}

// secretScanRule scans changed blob contents for secrets and denies if any are
// found. It is a push-only rule: EvaluateFetch always allows (fetch
// read-protection of secrets is via path_acl withholding, not content
// scanning — Task 9).
type secretScanRule struct {
	scanner    port.SecretScanner
	compileErr error // set when an extra pattern failed to compile
}

func (r *secretScanRule) Name() string { return secretScanName }

func (r *secretScanRule) EvaluatePush(req port.PushRequest) (port.Decision, error) {
	if r.compileErr != nil {
		return port.Decision{}, r.compileErr
	}
	if r.scanner == nil {
		return policy.Allow(), nil
	}
	for _, f := range req.ChangedFiles {
		// Only scan added/modified blobs with content. Deleted files have no
		// new blob to scan.
		if f.Status == "D" || len(f.Content) == 0 {
			continue
		}
		findings := r.scanner.Scan(f.Path, f.Content)
		if len(findings) == 0 {
			continue
		}
		// Report the first finding's path+line+rule (and the redacted snippet,
		// which the scanner has already masked). Never include the raw secret.
		f0 := findings[0]
		msg := fmt.Sprintf("secret found in %q at line %d (rule: %s)", f0.Path, f0.Line, f0.Rule)
		if f0.Snippet != "" {
			msg += "; snippet: " + f0.Snippet
		}
		return policy.Deny(r.Name(), msg), nil
	}
	return policy.Allow(), nil
}

func (r *secretScanRule) EvaluateFetch(port.FetchRequest) (port.Decision, error) {
	return policy.Allow(), nil
}

// parseExtraPatterns extracts a []regex.Pattern from params[key]. YAML decodes
// extra_patterns as a list of maps with "regex" and "name" string fields.
// Entries missing the required fields are dropped.
func parseExtraPatterns(params map[string]any, key string) []regex.Pattern {
	if params == nil {
		return nil
	}
	v, ok := params[key]
	if !ok {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []regex.Pattern
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		re, _ := m["regex"].(string)
		name, _ := m["name"].(string)
		if re == "" {
			continue
		}
		out = append(out, regex.Pattern{Regex: re, Name: name})
	}
	return out
}