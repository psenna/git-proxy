package access

import (
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

type fakeStore struct {
	creds map[string]port.Credentials
}

func (f fakeStore) CredentialsFor(repo string) (port.Credentials, bool) {
	c, ok := f.creds[repo]
	return c, ok
}

type fakeMatcher struct{ match func(string) bool }

func (f fakeMatcher) Match(repo string) bool { return f.match(repo) }

func TestDecide(t *testing.T) {
	matched := fakeMatcher{func(string) bool { return true }}
	unmatched := fakeMatcher{func(string) bool { return false }}
	profiled := fakeStore{creds: map[string]port.Credentials{"org/r.git": {Username: "u"}}}

	cases := []struct {
		name    string
		creds   port.CredentialStore
		public  port.RepoMatcher
		repo    string
		isWrite bool
		want    Decision
	}{
		{
			name:    "profiled creds ok read",
			creds:   profiled,
			public:  unmatched,
			repo:    "org/r.git",
			isWrite: false,
			want:    DecisionAllow,
		},
		{
			name:    "profiled creds ok write",
			creds:   profiled,
			public:  unmatched,
			repo:    "org/r.git",
			isWrite: true,
			want:    DecisionAllow,
		},
		{
			name:    "no creds read public matches",
			creds:   nil,
			public:  matched,
			repo:    "org/r.git",
			isWrite: false,
			want:    DecisionAllow,
		},
		{
			name:    "no creds write public matches denies",
			creds:   nil,
			public:  matched,
			repo:    "org/r.git",
			isWrite: true,
			want:    DecisionDeny,
		},
		{
			name:    "no creds read public no match denies",
			creds:   nil,
			public:  unmatched,
			repo:    "org/r.git",
			isWrite: false,
			want:    DecisionDeny,
		},
		{
			name:    "no creds write public no match denies",
			creds:   nil,
			public:  unmatched,
			repo:    "org/r.git",
			isWrite: true,
			want:    DecisionDeny,
		},
		{
			name:    "nil creds nil public read denies",
			creds:   nil,
			public:  nil,
			repo:    "org/r.git",
			isWrite: false,
			want:    DecisionDeny,
		},
		{
			name:    "nil creds nil public write denies",
			creds:   nil,
			public:  nil,
			repo:    "org/r.git",
			isWrite: true,
			want:    DecisionDeny,
		},
		{
			name:    "nil public but creds ok allows",
			creds:   profiled,
			public:  nil,
			repo:    "org/r.git",
			isWrite: false,
			want:    DecisionAllow,
		},
	}
	for _, c := range cases {
		got := Decide(c.creds, c.public, c.repo, c.isWrite)
		if got != c.want {
			t.Errorf("%s: Decide = %v, want %v", c.name, got, c.want)
		}
	}
}
