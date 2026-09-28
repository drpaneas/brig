package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brig-sh/brig/internal/secret"
)

// readCountingFake is the CLI's fake store with every Read counted, because a
// Read is the decrypt `brig plan` must never make.
type readCountingFake struct {
	*fakeStore
	reads int
}

func (f *readCountingFake) Read(name string) ([]byte, error) {
	f.reads++
	return f.fakeStore.Read(name)
}

// planHost is a bare host with one profile that needs a stored secret, and a
// fake store in place of the keychain whose reads are counted.
func planHost(t *testing.T) *readCountingFake {
	t.Helper()
	scratchHost(t)
	t.Setenv("BRIG_PROFILE_DIR", writeProfile(t, "name: planned\nimage: i\nguestHome: /home/p\n"+
		"binary: p\nmem: 1024\ncpus: 2\n"+
		"secrets:\n  - gh\n  - tok\n"+
		"env:\n  - name: GH_TOKEN\n    ref: secrets.gh\n"+
		"volumes:\n  - kind: tmpfs\n    path: .config\n"+
		"files:\n  - ref: secrets.tok\n    path: .config/cred\n"))
	f := &readCountingFake{fakeStore: newFake(t)}
	old := openStore
	openStore = func() (secret.Store, error) { return f, nil }
	t.Cleanup(func() { openStore = old })
	return f
}

type planDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Data       struct {
		Profile  string   `json:"profile"`
		Digest   string   `json:"digest"`
		Posture  string   `json:"posture"`
		Policies []string `json:"policies"`
		NoPolicy bool     `json:"noPolicy"`
		Egress   *struct {
			Default string `json:"default"`
		} `json:"egress"`
		Credentials []struct {
			Name     string `json:"name"`
			State    string `json:"state"`
			Required bool   `json:"required"`
		} `json:"credentials"`
	} `json:"data"`
}

// A required secret missing from the store is where `brig info` exits 6. The
// plan exits 0, names the credential as unresolved, and never reads the store.
func TestPlanExitsZeroOnAMissingRequiredSecret(t *testing.T) {
	f := planHost(t)
	f.seed("tok", "PLANTED-FILE-VALUE")

	out, err := captureStdout(t, func() error { return run([]string{"--json", "plan", "planned"}) })
	if err != nil {
		t.Fatalf("brig plan refused a missing secret: %v (exit %d)", err, exitCode(err))
	}
	if f.reads != 0 {
		t.Errorf("brig plan read %d secret values", f.reads)
	}
	if strings.Contains(out, "PLANTED-FILE-VALUE") {
		t.Fatalf("brig plan printed a secret value:\n%s", out)
	}
	var doc planDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("brig plan --json did not print parseable JSON: %v\n%s", err, out)
	}
	if doc.APIVersion != jsonAPIVersion || doc.Kind != "Plan" {
		t.Errorf("envelope is %q/%q, want %q/Plan", doc.APIVersion, doc.Kind, jsonAPIVersion)
	}
	states := map[string]string{}
	for _, c := range doc.Data.Credentials {
		states[c.Name] = c.State
	}
	if states["GH_TOKEN"] != "unresolved" {
		t.Errorf("GH_TOKEN is %q, want unresolved: %s", states["GH_TOKEN"], out)
	}
	if states[".config/cred"] != "resolved" {
		t.Errorf(".config/cred is %q, want resolved: %s", states[".config/cred"], out)
	}
	if !strings.HasPrefix(doc.Data.Digest, "sha256:") {
		t.Errorf("the plan carries no digest: %s", out)
	}
}

// The text form is the same view, and it too never reads the store.
func TestPlanTextNeverReadsTheStore(t *testing.T) {
	f := planHost(t)
	f.seed("gh", "PLANTED-ENV-VALUE")
	f.seed("tok", "PLANTED-FILE-VALUE")

	out, err := captureStdout(t, func() error { return run([]string{"plan", "planned"}) })
	if err != nil {
		t.Fatalf("brig plan: %v", err)
	}
	if f.reads != 0 {
		t.Errorf("brig plan read %d secret values", f.reads)
	}
	if strings.Contains(out, "PLANTED") {
		t.Fatalf("brig plan printed a secret value:\n%s", out)
	}
	for _, want := range []string{"GH_TOKEN", ".config/cred", "DIGEST"} {
		if !strings.Contains(out, want) {
			t.Errorf("the plan does not name %s:\n%s", want, out)
		}
	}
}

// --json reaches plan from both positions, as it reaches info.
func TestPlanTakesJSONInBothPositions(t *testing.T) {
	for _, args := range [][]string{{"--json", "plan", "planned"}, {"plan", "planned", "--json"}} {
		planHost(t)
		out, err := captureStdout(t, func() error { return run(args) })
		if err != nil {
			t.Fatalf("brig %s: %v", strings.Join(args, " "), err)
		}
		var doc planDoc
		if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Kind != "Plan" {
			t.Errorf("brig %s printed %q (%v)", strings.Join(args, " "), out, err)
		}
	}
	if !verbTakesGlobalJSON("plan", []string{"planned"}) {
		t.Error("verbTakesGlobalJSON does not know plan")
	}
	if !strings.Contains(jsonUnsupportedf("stop").Error(), "plan") {
		t.Error("the --json refusal does not name plan among the verbs that take it")
	}
}

// A policy attached to one session binds that session's plan and no other.
// The lookup runs through Load and the session's slug, the path #172 broke,
// so it is driven through the ref here and not set on a Config by hand.
func TestPlanListsThePolicyBoundToASession(t *testing.T) {
	planHost(t)
	dir := t.TempDir()
	t.Setenv("BRIG_POLICY_DIR", dir)
	writePolicyFile(t, dir, "no-net", noNetBody)
	if _, err := captureStdout(t, func() error {
		return run([]string{"policy", "attach", "no-net", "planned", "-n", "x"})
	}); err != nil {
		t.Fatalf("policy attach: %v", err)
	}

	plan := func(ref string) planDoc {
		t.Helper()
		out, err := captureStdout(t, func() error { return run([]string{"--json", "plan", ref}) })
		if err != nil {
			t.Fatalf("brig plan %s: %v", ref, err)
		}
		var doc planDoc
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("brig plan %s: %v\n%s", ref, err, out)
		}
		return doc
	}

	bound := plan("planned@x").Data
	if bound.NoPolicy || strings.Join(bound.Policies, ",") != "no-net" {
		t.Errorf("planned@x: noPolicy %v, policies %v, want no-net", bound.NoPolicy, bound.Policies)
	}
	if bound.Egress == nil || bound.Egress.Default != "deny" {
		t.Errorf("planned@x: egress %+v, want default deny", bound.Egress)
	}
	if bound.Posture != "isolated" {
		t.Errorf("planned@x: posture %q, want isolated under a policy", bound.Posture)
	}

	free := plan("planned").Data
	if !free.NoPolicy || len(free.Policies) != 0 || free.Egress != nil {
		t.Errorf("planned: noPolicy %v, policies %v, egress %+v, want none bound",
			free.NoPolicy, free.Policies, free.Egress)
	}
}

// Completion offers the verb, a ref after it, and --json on its line.
func TestCompletionKnowsPlan(t *testing.T) {
	completionHost(t)
	_, got := complete([]string{""})
	if !contains(got, "plan") {
		t.Errorf("the verbs offered are %v, want plan among them", got)
	}
	if !refVerbs["plan"] {
		t.Error("plan does not complete a ref")
	}
	if _, got := complete([]string{"plan", "claude", "--j"}); !contains(got, "--json") {
		t.Errorf("after `brig plan claude --j` completion offers %v, want --json", got)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
