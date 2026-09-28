package wrap

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/brig-sh/brig/internal/creds"
	"github.com/brig-sh/brig/internal/policy"
	"github.com/brig-sh/brig/internal/secret"
)

// readCountingStore lists what it holds and counts every Read, which is the
// decrypt a plan must never make. It answers a Read with the planted value, so
// a plan that reads it has the value in hand to leak.
type readCountingStore struct {
	list  []secret.Secret
	value string
	reads *int
}

func (s readCountingStore) Read(string) ([]byte, error) {
	*s.reads++
	return []byte(s.value), nil
}

func (s readCountingStore) List() ([]secret.Secret, error) { return s.list, nil }

// planProfile delivers one stored secret as an environment variable, one as a
// file, and forwards one variable from the shell, so every way a credential
// reaches the guest is in the plan.
const planProfile = "secrets:\n  - gh\n  - tok\n" +
	"env:\n  - name: GH_TOKEN\n    ref: secrets.gh\n  - name: SHELL_TOK\n    ref: env.SHELL_TOK\n" +
	"volumes:\n  - kind: tmpfs\n    path: .config\n" +
	"files:\n  - ref: secrets.tok\n    path: .config/cred\n    mode: \"0600\"\n"

// The plan is the permission view a reader asks for before any secret is
// opened. A value seeded in the store, and one in the shell, appear in no field
// of either form, and the store is never read: listing it is what says a
// secret is there.
func TestPlanNeverReadsOrPrintsASecretValue(t *testing.T) {
	const planted = "PLANTED-SECRET-VALUE"
	const plantedEnv = "PLANTED-SHELL-VALUE"
	t.Setenv("SHELL_TOK", plantedEnv)

	c := bindingConfig(t, planProfile)
	c.Runtime = nil
	reads := 0
	c.OpenStore = func() (creds.SecretReader, error) {
		return readCountingStore{
			list:  []secret.Secret{{Name: "gh"}, {Name: "tok"}},
			value: planted,
			reads: &reads,
		}, nil
	}

	d := c.Plan()
	blob, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	c.Out = &text
	c.PrintPlan(d)

	if reads != 0 {
		t.Errorf("the plan read %d secret values from the store, want none", reads)
	}
	for _, out := range []string{string(blob), text.String()} {
		if strings.Contains(out, planted) || strings.Contains(out, plantedEnv) {
			t.Fatalf("the plan printed a credential value:\n%s", out)
		}
	}

	// The names are there with their delivery, which is the point of the view.
	got := map[string]PlanCredential{}
	for _, cr := range d.Credentials {
		got[cr.Name] = cr
	}
	for name, want := range map[string]PlanCredential{
		"GH_TOKEN":     {Delivery: "env", Source: "secret", Secret: "gh", State: "resolved"},
		"SHELL_TOK":    {Delivery: "env", Source: "environment", State: "resolved"},
		".config/cred": {Delivery: "file", Source: "secret", Secret: "tok", State: "resolved"},
	} {
		g := got[name]
		if g.Delivery != want.Delivery || g.Source != want.Source || g.Secret != want.Secret || g.State != want.State {
			t.Errorf("%s = %+v, want %+v", name, g, want)
		}
	}
}

// A required secret missing from the store is named and marked unresolved,
// and the plan still answers.
func TestPlanMarksAMissingRequiredSecretUnresolved(t *testing.T) {
	c := bindingConfig(t, planProfile)
	reads := 0
	c.OpenStore = func() (creds.SecretReader, error) {
		return readCountingStore{reads: &reads}, nil
	}
	d := c.Plan()
	var found bool
	for _, cr := range d.Credentials {
		if cr.Name == "GH_TOKEN" {
			found = true
			if cr.State != "unresolved" || !cr.Required {
				t.Errorf("GH_TOKEN = %+v, want required and unresolved", cr)
			}
		}
	}
	if !found {
		t.Errorf("the missing credential is not named: %+v", d.Credentials)
	}
	if reads != 0 {
		t.Errorf("the plan read the store %d times", reads)
	}
}

// plan --json and info --json read the same Config, so they agree on the
// network, the image reference and the pull policy.
func TestPlanAgreesWithInfo(t *testing.T) {
	c := bindingConfig(t, "")
	c.Image, c.Pull, c.Network = "ghcr.io/brig-sh/x:1", "always", NetIsolated
	p, i := c.Plan(), c.InfoData(creds.Set{})
	if p.Network != i.Network || p.Image.Ref != i.Image.Ref || p.Image.Pull != i.Image.Pull {
		t.Errorf("plan says %q %+v, info says %q %+v", p.Network, p.Image, i.Network, i.Image)
	}
}

// The guest home is named with its host directory, its guest path and its
// mode, and the project the same way when the run has one.
func TestPlanStatesTheHomeAndTheProject(t *testing.T) {
	c := bindingConfig(t, "")
	d := c.Plan()
	if d.Home.Host != c.Workspace || d.Home.Guest != c.Profile.GuestHome || d.Home.Mode != "read-write" {
		t.Errorf("home = %+v", d.Home)
	}
	if d.Project != nil {
		t.Errorf("a run with no project planned one: %+v", d.Project)
	}
	c.Project, c.ProjectReal, c.GuestProject = "/p", "/real/p", "/work/p"
	d = c.Plan()
	if d.Project == nil || d.Project.Host != "/real/p" || d.Project.Guest != "/work/p" || d.Project.Mode != "read-write" {
		t.Errorf("project = %+v", d.Project)
	}
}

// Every bound policy is listed, and a field of its own says when none binds,
// so a reader does not have to infer it from an empty list.
func TestPlanSaysWhenNoPolicyBinds(t *testing.T) {
	c := bindingConfig(t, "")
	d := c.Plan()
	if !d.NoPolicy || d.Policies == nil || len(d.Policies) != 0 {
		t.Errorf("no policy: noPolicy %v, policies %#v", d.NoPolicy, d.Policies)
	}
	c.Policies = []string{"locked", "base"}
	c.Egress = policy.Egress{Default: "deny", Allow: []policy.Rule{{Host: "b.example"}, {Host: "a.example"}}}
	d = c.Plan()
	if d.NoPolicy || strings.Join(d.Policies, ",") != "base,locked" {
		t.Errorf("bound: noPolicy %v, policies %v", d.NoPolicy, d.Policies)
	}
	if d.Egress == nil || d.Egress.Default != "deny" || len(d.Egress.Allow) != 2 || d.Egress.Allow[0].Host != "a.example" {
		t.Errorf("egress = %+v", d.Egress)
	}
}

// The digest is the same for the same inputs, whatever order the lists came
// in, and moves when any permission moves.
func TestPlanDigestIsStableAndMovesWithPermissions(t *testing.T) {
	base := func() *Config {
		c := bindingConfig(t, planProfile)
		c.Workspace = "/home-dir"
		c.Policies = []string{"a", "b"}
		c.Egress = policy.Egress{Default: "deny", Allow: []policy.Rule{{Host: "x.example"}, {Host: "y.example"}}}
		c.Mem, c.CPUs = 2048, 2
		reads := 0
		c.OpenStore = func() (creds.SecretReader, error) {
			return readCountingStore{list: []secret.Secret{{Name: "gh"}, {Name: "tok"}}, reads: &reads}, nil
		}
		return c
	}
	want := base().Plan().Digest
	if !strings.HasPrefix(want, "sha256:") {
		t.Fatalf("digest %q is not a sha256", want)
	}
	if again := base().Plan().Digest; again != want {
		t.Errorf("the same inputs gave %s then %s", want, again)
	}
	reordered := base()
	reordered.Policies = []string{"b", "a"}
	reordered.Egress.Allow = []policy.Rule{{Host: "y.example"}, {Host: "x.example"}}
	if got := reordered.Plan().Digest; got != want {
		t.Errorf("reordering the lists moved the digest: %s, want %s", got, want)
	}

	for name, change := range map[string]func(c *Config){
		"home":    func(c *Config) { c.Workspace = "/other" },
		"network": func(c *Config) { c.Network = NetOffline },
		"policy":  func(c *Config) { c.Policies = []string{"a"} },
		"egress":  func(c *Config) { c.Egress.Allow = c.Egress.Allow[:1] },
		"mem":     func(c *Config) { c.Mem = 4096 },
		"cpus":    func(c *Config) { c.CPUs = 4 },
		"image":   func(c *Config) { c.Image = "other:1" },
		"credential": func(c *Config) {
			reads := 0
			c.OpenStore = func() (creds.SecretReader, error) {
				return readCountingStore{list: []secret.Secret{{Name: "tok"}}, reads: &reads}, nil
			}
		},
	} {
		c := base()
		change(c)
		if got := c.Plan().Digest; got == want {
			t.Errorf("changing the %s left the digest at %s", name, got)
		}
	}
}

// With no runtime on PATH the plan still answers, and marks the rows that
// needed one.
func TestPlanWithoutARuntimeMarksTheRuntimeRows(t *testing.T) {
	c := bindingConfig(t, "")
	c.Runtime = nil
	d := c.Plan()
	if d.Runtime.Available {
		t.Error("the runtime is marked available with none on PATH")
	}
	if d.Isolation == "" || d.Profile == "" || d.Sandbox == "" {
		t.Errorf("the plan left rows empty: %+v", d)
	}
}
