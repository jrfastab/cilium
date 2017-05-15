// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Repository is a list of policy rules which in combination form the security
// policy. A policy repository can be
type Repository struct {
	// Mutex protects the whole policy tree
	Mutex sync.RWMutex
	rules []*rule
}

// NewPolicyRepository allocates a new policy repository
func NewPolicyRepository() *Repository {
	return &Repository{}
}

// traceState is an internal structure used to collect information
// while determing policy decision
type traceState struct {
	// selectedRules is the number of rules with matching EndpointSelector
	selectedRules int

	// ruleID is the rule ID currently being evaluated
	ruleID int
}

// CanReachRLocked evaluates the policy repository for the provided search
// context and returns the verdict or api.Undecided if no rule matches. The
// policy repository mutex must be held.
func (p *Repository) CanReachRLocked(ctx *SearchContext) api.Decision {
	decision := api.Undecided
	state := traceState{}

	for i, r := range p.rules {
		state.ruleID = i
		switch r.canReach(ctx, &state) {
		// The rule contained a constraint which was not met, this
		// connection is not allowed
		case api.Denied:
			return api.Denied

		// The rule allowed the connection but a later rule may impose
		// additional constraints, so we store the decision but allow
		// it to be overwritten by an additional requirement
		case api.Allowed:
			decision = api.Allowed
		}
	}

	ctx.PolicyTrace("%d rules matched", state.selectedRules)

	return decision
}

// AllowsRLocked evaluates the policy repository for the provided search
// context and return the verdict. If no matching policy allows for the
// connection, the request will be denied. The policy repository mutex must be
// held.
func (p *Repository) AllowsRLocked(ctx *SearchContext) api.Decision {
	ctx.PolicyTrace("Tracing %s\n", ctx.String())
	decision := api.Denied

	if len(p.rules) == 0 {
		ctx.PolicyTrace("  No rules found\n")
	} else {
		if p.CanReachRLocked(ctx) == api.Allowed {
			decision = api.Allowed
		}
	}

	ctx.PolicyTrace("Result: %s\n", strings.ToUpper(decision.String()))

	return decision
}

// ResolveL4Policy resolves the L4 policy for a set of endpoints by searching
// the policy repository for `PortRule` rules that are attached to a `Rule`
// where the EndpointSelector matches `ctx.To`. `ctx.From` takes no effect and
// is ignored in the search.  If multiple `PortRule` rules are found, all rules
// are merged together. If rules contains overlapping port definitions, the first
// rule found in the repository takes precedence.
//
// TODO: Need better rule merging on conflicting port definitions, concat l7 rules?
func (p *Repository) ResolveL4Policy(ctx *SearchContext) *L4Policy {
	result := NewL4Policy()

	if ctx.EgressL4Only {
		ctx.PolicyTrace("Resolving egress port policy for %+v\n", ctx.To)
	} else if ctx.IngressL4Only {
		ctx.PolicyTrace("Resolving ingress port policy for %+v\n", ctx.To)
	} else {
		ctx.PolicyTrace("Resolving port policy for %+v\n", ctx.To)
	}

	state := traceState{}
	for _, r := range p.rules {
		r.resolveL4Policy(ctx, &state, result)
		state.ruleID++
	}

	ctx.PolicyTrace("%d rules matched\n", state.selectedRules)
	return result
}

// SearchRLocked searches the policy repository for rules which match the
// specified labels and will return an array of all rules which matched.
func (p *Repository) SearchRLocked(labels labels.LabelArray) api.Rules {
	result := api.Rules{}

	for _, r := range p.rules {
		if r.Labels.Contains(labels) {
			result = append(result, &r.Rule)
		}
	}

	return result
}

// Add inserts a rule into the policy repository
func (p *Repository) Add(r api.Rule) error {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()

	realRule := &rule{Rule: r}
	if err := realRule.validate(); err != nil {
		return err
	}

	p.rules = append(p.rules, realRule)
	return nil
}

// AddListLocked inserts a rule into the policy repository with the repository already locked
func (p *Repository) AddListLocked(rules api.Rules) error {
	// Validate entire rule list first and only append array if
	// all rules are valid
	newList := make([]*rule, len(rules))
	for i := range rules {
		newList[i] = &rule{Rule: *rules[i]}
		if err := newList[i].validate(); err != nil {
			return err
		}
	}

	p.rules = append(p.rules, newList...)
	return nil
}

// AddList inserts a rule into the policy repository
func (p *Repository) AddList(rules api.Rules) error {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.AddListLocked(rules)
}

// DeleteByLabelsLocked deletes all rules in the policy repository which
// contain the specified labels
func (p *Repository) DeleteByLabelsLocked(labels labels.LabelArray) int {
	deleted := 0
	new := p.rules[:0]

	for _, r := range p.rules {
		if !r.Labels.Contains(labels) {
			new = append(new, r)
		} else {
			deleted++
		}
	}

	if deleted > 0 {
		p.rules = new
	}

	return deleted
}

// DeleteByLabels deletes all rules in the policy repository which contain the
// specified labels
func (p *Repository) DeleteByLabels(labels labels.LabelArray) int {
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	return p.DeleteByLabelsLocked(labels)
}

// JSONMarshalRules returns a slice of policy rules as string in JSON
// representation
func JSONMarshalRules(rules api.Rules) string {
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// GetJSON returns all rules of the policy repository as string in JSON
// representation
func (p *Repository) GetJSON() string {
	p.Mutex.RLock()
	defer p.Mutex.RUnlock()

	result := api.Rules{}
	for _, r := range p.rules {
		result = append(result, &r.Rule)
	}

	return JSONMarshalRules(result)
}
