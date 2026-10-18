package cli

import "strings"

// Command is the source of truth for usage() and shell completion.
type Command struct {
	Name        string
	Summary     string
	Args        []string
	Flags       []Flag
	Subcommands []Command
}

type Flag struct {
	Name string // without leading dash, e.g. "config"
	Arg  string // metavariable, e.g. "PATH"
	Help string
	File bool
}

func commonConfigFlag() Flag {
	return Flag{Name: "config", Arg: "PATH", Help: "yaml config (or $ROUTEPROXY_CONFIG)", File: true}
}

func Commands() []Command {
	cfg := commonConfigFlag()
	return []Command{
		{Name: "generate", Summary: "YAML → sing-box JSON (mixed SOCKS)", Flags: []Flag{cfg}},
		{
			Name:    "generate-sfa",
			Summary: "YAML → SFA JSON (TUN / Android VPN)",
			Flags:   []Flag{cfg, {Name: "out", Arg: "PATH", Help: "output JSON (`-` for stdout)", File: true}},
		},
		{Name: "check", Summary: "generate + sing-box check", Flags: []Flag{cfg}},
		{Name: "apply", Summary: "generate, check, restart via apply.commands", Flags: []Flag{cfg}},
		{
			Name:    "add",
			Summary: "import vless://, tg://socks, t.me/proxy",
			Args:    []string{"url"},
			Flags: []Flag{
				cfg,
				{Name: "purpose", Arg: "LIST", Help: "comma purposes (default auto,telegram)"},
				{Name: "name", Arg: "NAME", Help: "optional proxy name"},
			},
		},
		{Name: "telegram-urls", Summary: "print MTProto links + local SOCKS", Flags: []Flag{cfg}},
		{Name: "why", Summary: "explain outbound for a host", Args: []string{"host"}, Flags: []Flag{cfg}},
		{Name: "probe", Summary: "healthz + mixed smoke", Flags: []Flag{cfg}},
		{Name: "checker", Summary: "MTProto TCP failover (:1443+)", Flags: []Flag{cfg}},
		{
			Name:    "completion",
			Summary: "print bash or zsh completion script",
			Args:    []string{"shell"},
			Subcommands: []Command{
				{Name: "bash", Summary: "Bash completion on stdout"},
				{Name: "zsh", Summary: "Zsh completion on stdout"},
			},
		},
		{Name: "help", Summary: "show this help"},
	}
}

func CommandNames() []string {
	var out []string
	for _, c := range Commands() {
		out = append(out, c.Name)
	}
	return out
}

func Usage() string {
	var b strings.Builder
	b.WriteString("rpctl — routeproxy control\n\n")
	for _, c := range Commands() {
		var line strings.Builder
		line.WriteString("  rpctl " + c.Name)
		for _, a := range c.Args {
			line.WriteString(" <" + a + ">")
		}
		b.WriteString(padCmd(line.String(), c.Summary) + "\n")
	}
	b.WriteString("\nFlags (after command): -config PATH  (or $ROUTEPROXY_CONFIG)\n")
	b.WriteString("Completion: eval \"$(rpctl completion bash)\"  or  eval \"$(rpctl completion zsh)\"\n")
	return b.String()
}

func padCmd(left, summary string) string {
	if len(left) >= 26 {
		return left + "  " + summary
	}
	return left + spaces(26-len(left)) + summary
}

func spaces(n int) string {
	return strings.Repeat(" ", n)
}
