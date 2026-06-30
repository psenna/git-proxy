package main

import (
	"fmt"

	"github.com/psenna/git-proxy/internal/version"
)

func main() { fmt.Println("git-proxy", version.Version) }