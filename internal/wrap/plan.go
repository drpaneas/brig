package wrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/brig-sh/brig/internal/creds"
	"github.com/brig-sh/brig/internal/policy"
)

// Plan is `brig plan`: the permissions of a run of this Config, read without
// opening a secret.
//
// It is built from the Config Load resolved, the same one `brig info` and a
// run read, so the three cannot disagree about the home, the network or the
// image. What it does not share with them is BuildEnv. BuildEnv reads every
// needed secret out of the store, fails on a missing one, and writes the git
// helper into the guest home. The plan lists the store instead, which reads
// names and no values, and it writes nothing. So a missing secret is a row
// marked unresolved and the command still answers.
func (c *Config) Plan() PlanDocument {
	listing, listed := c.listSecrets()
	stored := func(name string) (bool, bool) {
		if !listed {
			return false, false
		}
		_, ok := listing[name]
		return ok, true
	}
	d := PlanDocument{
		Session: c.RawName,
		Profile: c.Profile.Name,
		Sandbox: c.VMName,
		Runtime: PlanRuntime{
			InfoRuntime: c.infoRuntime(),
			Backend:     c.hypervisor(),
		},
		Isolation: c.isolationLine(),
		Home:      PlanMount{Host: c.Workspace, Guest: c.Profile.GuestHome, Mode: "read-write"},
		Image:     InfoImage{Ref: c.Image, Pull: c.Pull},
		Verify:    c.infoVerify(),
		Network:   c.Network.Line(),
		Posture:   string(c.Network),
		Ports:     []string{},
		Policies:  []string{},
		NoPolicy:  len(c.Policies) == 0,
		Limits:    PlanLimits{Mem: c.Mem, CPUs: c.CPUs},
	}
	if c.Project != "" {
		d.Project = &PlanMount{Host: c.ProjectReal, Guest: c.GuestProject, Mode: "read-write"}
	}
	if c.projectRefused != nil {
		d.ProjectRefused = c.projectRefused.Error()
	}
	for _, p := range c.Publish {
		d.Ports = append(d.Ports, p.String())
	}
	sort.Strings(d.Ports)
	d.Policies = append(d.Policies, c.Policies...)
	sort.Strings(d.Policies)
	if c.Egress.Default != "" {
		d.Egress = &PlanEgress{
			Default: c.Egress.Default,
			Allow:   sortedRules(c.Egress.Allow),
			Deny:    sortedRules(c.Egress.Deny),
		}
	}
	d.Credentials = []PlanCredential{}
	for _, p := range creds.Preview(c.Profile, c.Env, stored, os.LookupEnv, creds.Options{
		AllowRefs:   c.AllowRefs,
		AllowDenied: c.AllowDenied,
	}) {
		d.Credentials = append(d.Credentials, PlanCredential(p))
	}
	d.Digest = planDigest(d)
	return d
}

// PlanDocument is the Plan payload. Every list in it is sorted and none is
// null, so two plans of the same run encode to the same bytes and the digest
// over them is stable.
type PlanDocument struct {
	Session   string      `json:"session,omitempty"`
	Profile   string      `json:"profile"`
	Sandbox   string      `json:"sandbox"`
	Runtime   PlanRuntime `json:"runtime"`
	Isolation string      `json:"isolation"`
	Home      PlanMount   `json:"home"`
	Project   *PlanMount  `json:"project,omitempty"`
	// ProjectRefused is why the project this session remembers is not
	// mounted, as in the Info payload.
	ProjectRefused string     `json:"projectRefused,omitempty"`
	Image          InfoImage  `json:"image"`
	Verify         InfoVerify `json:"verify"`
	// Network is the sentence the Info payload carries, and Posture the word.
	Network string   `json:"network"`
	Posture string   `json:"posture"`
	Ports   []string `json:"ports"`
	// Policies names every policy bound to this run. NoPolicy says none is,
	// so a reader does not have to infer it from an empty list.
	Policies    []string         `json:"policies"`
	NoPolicy    bool             `json:"noPolicy"`
	Egress      *PlanEgress      `json:"egress,omitempty"`
	Credentials []PlanCredential `json:"credentials"`
	Limits      PlanLimits       `json:"limits"`
	// Digest is sha256 over this document with Digest empty.
	Digest string `json:"digest"`
}

// PlanRuntime is the runtime and the backend under it. Backend is the
// hypervisor the profile or BRIG_HYPERVISOR names, empty for the runtime's
// own default.
type PlanRuntime struct {
	InfoRuntime
	Backend string `json:"backend,omitempty"`
}

// PlanMount is one host directory the guest reaches, where it lands and how.
type PlanMount struct {
	Host  string `json:"host"`
	Guest string `json:"guest"`
	Mode  string `json:"mode"`
}

// PlanEgress is the merged rule set of every bound policy.
type PlanEgress struct {
	Default string        `json:"default"`
	Allow   []policy.Rule `json:"allow"`
	Deny    []policy.Rule `json:"deny"`
}

// PlanLimits is what the guest is given: memory in MB and vCPUs.
type PlanLimits struct {
	Mem  int `json:"mem"`
	CPUs int `json:"cpus"`
}

// PlanCredential is one credential by name, delivery and source. It is
// creds.Planned with JSON names. Plan converts one to the other, so a field
// added to one and not the other fails to build.
type PlanCredential struct {
	Name     string `json:"name"`
	Delivery string `json:"delivery"`
	Source   string `json:"source,omitempty"`
	Secret   string `json:"secret,omitempty"`
	Required bool   `json:"required"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
}

// sortedRules copies rules in host, then CIDR order, never nil.
func sortedRules(rules []policy.Rule) []policy.Rule {
	out := append([]policy.Rule{}, rules...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].CIDR < out[j].CIDR
	})
	return out
}

// planDigest is the digest a plan carries. The encoding is Go's for the
// struct, whose field order is fixed, over lists Plan has already sorted.
func planDigest(d PlanDocument) string {
	d.Digest = ""
	blob, err := json.Marshal(d)
	if err != nil {
		// Every field is a string, a number, a bool or a list of them.
		panic(err)
	}
	sum := sha256.Sum256(blob)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PrintPlan writes the plan as aligned rows to Out, the form a person reads.
func (c *Config) PrintPlan(d PlanDocument) {
	var rows []envelopeRow
	if d.Session != "" {
		rows = append(rows, envelopeRow{"SESSION", d.Session})
	}
	runtimeLine := "unavailable (no runtime on PATH)"
	if d.Runtime.Available {
		runtimeLine = d.Runtime.Kind + " (" + d.Runtime.Bin + ")"
		if d.Runtime.Backend != "" {
			runtimeLine += ", backend " + d.Runtime.Backend
		}
	}
	rows = append(rows,
		envelopeRow{"PROFILE", d.Profile},
		envelopeRow{"SANDBOX", d.Sandbox},
		envelopeRow{"RUNTIME", runtimeLine},
		envelopeRow{"ISOLATION", d.Isolation},
		envelopeRow{"HOME", fmt.Sprintf("%s (%s, mounted at %s)", d.Home.Host, d.Home.Mode, d.Home.Guest)},
	)
	if d.Project != nil {
		rows = append(rows, envelopeRow{"PROJECT",
			fmt.Sprintf("%s (%s, mounted at %s)", d.Project.Host, d.Project.Mode, d.Project.Guest)})
	}
	// The refusal runs to several lines, and each takes a row of its own so
	// the column stays aligned.
	if d.ProjectRefused != "" {
		for i, line := range strings.Split("not mounted: "+d.ProjectRefused, "\n") {
			rows = append(rows, envelopeRow{labelOnce(i, "PROJECT"), line})
		}
	}
	rows = append(rows,
		envelopeRow{"IMAGE", fmt.Sprintf("%s (pull %s)", d.Image.Ref, d.Image.Pull)},
		envelopeRow{"VERIFY", c.verifyLine()},
		envelopeRow{"NETWORK", d.Network},
	)
	for i, p := range d.Ports {
		rows = append(rows, envelopeRow{labelOnce(i, "PORTS"), p})
	}
	if d.NoPolicy {
		rows = append(rows, envelopeRow{"POLICY", "(none)"})
	} else {
		rows = append(rows, envelopeRow{"POLICY", strings.Join(d.Policies, ", ")})
	}
	if d.Egress != nil {
		rows = append(rows, envelopeRow{"EGRESS", "default " + d.Egress.Default})
		for _, r := range d.Egress.Allow {
			rows = append(rows, envelopeRow{"", "allow " + ruleText(r)})
		}
		for _, r := range d.Egress.Deny {
			rows = append(rows, envelopeRow{"", "deny " + ruleText(r)})
		}
	}
	if len(d.Credentials) == 0 {
		rows = append(rows, envelopeRow{"CREDENTIALS", "(none)"})
	}
	for i, cr := range d.Credentials {
		rows = append(rows, envelopeRow{labelOnce(i, "CREDENTIALS"), credentialText(cr)})
	}
	rows = append(rows,
		envelopeRow{"LIMITS", fmt.Sprintf("%d MB, %d vCPUs", d.Limits.Mem, d.Limits.CPUs)},
		envelopeRow{"DIGEST", d.Digest},
	)
	writeRows(c.Out, rows)
}

// labelOnce is the label on the first row of a group and blank on the rest,
// the way the PORTS rows of the envelope read.
func labelOnce(i int, label string) string {
	if i == 0 {
		return label
	}
	return ""
}

func ruleText(r policy.Rule) string {
	if r.Host != "" {
		return r.Host
	}
	return r.CIDR
}

// credentialText is one CREDENTIALS row: the name, how it arrives, and where
// from or why not. Names only.
func credentialText(cr PlanCredential) string {
	var detail string
	switch cr.State {
	case creds.StateResolved:
		detail = "from the environment"
		if cr.Source == creds.SourceSecret {
			detail = "from the secret " + cr.Secret
		}
	default:
		detail = cr.State + ": " + cr.Reason
	}
	if cr.Required && cr.State != creds.StateResolved {
		detail += " (required)"
	}
	return fmt.Sprintf("%s (%s) %s", cr.Name, cr.Delivery, detail)
}
