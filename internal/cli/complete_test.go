package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"routeproxy/internal/cli"
)

func TestUsageListsEveryCommand(t *testing.T) {
	u := cli.Usage()
	for _, c := range cli.Commands() {
		if !strings.Contains(u, "rpctl "+c.Name) {
			t.Errorf("usage missing %s", c.Name)
		}
	}
	if !strings.Contains(u, "completion bash") {
		t.Fatal("usage should mention completion install")
	}
}

func TestBashAndZshCoverSpec(t *testing.T) {
	bash := cli.Bash()
	zsh := cli.Zsh()
	if !strings.HasPrefix(zsh, "#compdef rpctl\n") {
		t.Fatal("zsh must start with #compdef")
	}
	if !strings.Contains(zsh, `_arguments \`) && !strings.Contains(zsh, `_arguments -S \`) {
		t.Fatal("zsh _arguments must continue with backslash")
	}
	for _, c := range cli.Commands() {
		if !strings.Contains(bash, c.Name) {
			t.Errorf("bash missing command %s", c.Name)
		}
		if !strings.Contains(zsh, c.Name) {
			t.Errorf("zsh missing command %s", c.Name)
		}
		for _, f := range c.Flags {
			want := "-" + f.Name
			if !strings.Contains(bash, want) {
				t.Errorf("bash missing flag %s on %s", want, c.Name)
			}
			if !strings.Contains(zsh, want) {
				t.Errorf("zsh missing flag %s on %s", want, c.Name)
			}
		}
		for _, s := range c.Subcommands {
			if !strings.Contains(bash, s.Name) || !strings.Contains(zsh, s.Name) {
				t.Errorf("completion missing subcommand %s", s.Name)
			}
		}
	}
}

func TestContribMatchesGenerator(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	check := func(rel, got string) {
		t.Helper()
		path := filepath.Join(root, rel)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run make completion)", rel, err)
		}
		if string(raw) != got {
			t.Fatalf("%s is stale; run: make completion", rel)
		}
	}
	check("contrib/completions/rpctl.bash", cli.Bash())
	check("contrib/completions/_rpctl", cli.Zsh())
}
