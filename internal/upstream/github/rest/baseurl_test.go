package rest

import "testing"

func TestBaseURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		err  bool
	}{
		{"empty defaults to api.github.com", "", "https://api.github.com", false},
		{"plain github.com", "https://github.com", "https://api.github.com", false},
		{"github.com with path", "https://github.com/", "https://api.github.com", false},
		{"github.com with port ignored on host match", "https://github.com:443", "https://api.github.com", false},
		{"GHES root", "https://ghes.example.com", "https://ghes.example.com/api/v3", false},
		{"GHES root trailing slash", "https://ghes.example.com/", "https://ghes.example.com/api/v3", false},
		{"GHES with port", "https://ghes.example.com:8443", "https://ghes.example.com:8443/api/v3", false},
		{"GHES scheme-relative defaults https", "//ghes.example.com", "https://ghes.example.com/api/v3", false},
		{"malformed", "://not-a-url", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := BaseURL(tc.in)
			if tc.err {
				if err == nil {
					t.Fatalf("BaseURL(%q) = %q, nil; want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("BaseURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("BaseURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}