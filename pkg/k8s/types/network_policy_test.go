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

package k8s

import (
	"testing"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type K8sSuite struct{}

var _ = Suite(&K8sSuite{})

func (s *K8sSuite) TestParseNetworkPolicy(c *C) {
	netPolicy := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				{
					From: []v1beta1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"foo3": "bar3",
									"foo4": "bar4",
								},
							},
						},
					},
					Ports: []v1beta1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.Int,
								IntVal: 80,
							},
						},
					},
				},
			},
		},
	}

	rules, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8s.PodNamespaceLabel, v1.NamespaceDefault, k8s.LabelSource),
			labels.NewLabel("foo3", "bar3", k8s.LabelSource),
			labels.NewLabel("foo4", "bar4", k8s.LabelSource),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8s.PodNamespaceLabel, v1.NamespaceDefault, k8s.LabelSource),
			labels.NewLabel("foo1", "bar1", k8s.LabelSource),
			labels.NewLabel("foo2", "bar2", k8s.LabelSource),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	repo := policy.NewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.CanReachRLocked(&ctx), Equals, api.Allowed)

	result := repo.ResolveL4Policy(&ctx)
	c.Assert(result, DeepEquals, &policy.L4Policy{
		Ingress: policy.L4PolicyMap{
			"80/tcp": policy.L4Filter{
				Port: 80, Protocol: "tcp", L7Parser: "",
				L7RedirectPort: 0, L7Rules: []policy.AuxRule(nil),
			},
		},
		Egress: policy.L4PolicyMap{},
	})

	ctx.To = labels.LabelArray{
		labels.NewLabel("foo2", "bar2", k8s.LabelSource),
	}

	// ctx.To needs to have all labels from the policy in order to be accepted
	c.Assert(repo.CanReachRLocked(&ctx), Not(Equals), api.Allowed)

	ctx = policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel("foo3", "bar3", k8s.LabelSource),
		},
		To: labels.LabelArray{
			labels.NewLabel("foo1", "bar1", k8s.LabelSource),
			labels.NewLabel("foo2", "bar2", k8s.LabelSource),
		},
		Trace: policy.TRACE_VERBOSE,
	}
	// ctx.From also needs to have all labels from the policy in order to be accepted
	c.Assert(repo.CanReachRLocked(&ctx), Not(Equals), api.Allowed)
}

func (s *K8sSuite) TestParseNetworkPolicyUnknownProto(c *C) {
	netPolicy := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				{
					Ports: []v1beta1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{
								Type:   intstr.String,
								StrVal: "unknown",
							},
						},
					},
				},
			},
		},
	}

	rules, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, Not(IsNil))
	c.Assert(len(rules), Equals, 0)
}

func (s *K8sSuite) TestParseNetworkPolicyEmptyFrom(c *C) {
	// From missing, all sources should be allowed
	netPolicy1 := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
				},
			},
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				{},
			},
		},
	}

	rules, err := ParseNetworkPolicy(netPolicy1)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)

	ctx := policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8s.PodNamespaceLabel, v1.NamespaceDefault, k8s.LabelSource),
			labels.NewLabel("foo0", "bar0", k8s.LabelSource),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8s.PodNamespaceLabel, v1.NamespaceDefault, k8s.LabelSource),
			labels.NewLabel("foo1", "bar1", k8s.LabelSource),
		},
		Trace: policy.TRACE_VERBOSE,
	}

	repo := policy.NewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.CanReachRLocked(&ctx), Equals, api.Allowed)

	// Empty From rules, all sources should be allowed
	netPolicy2 := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
				},
			},
			Ingress: []v1beta1.NetworkPolicyIngressRule{
				{
					From:  []v1beta1.NetworkPolicyPeer{},
					Ports: []v1beta1.NetworkPolicyPort{},
				},
			},
		},
	}

	rules, err = ParseNetworkPolicy(netPolicy2)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
	repo = policy.NewPolicyRepository()
	repo.AddList(rules)
	c.Assert(repo.CanReachRLocked(&ctx), Equals, api.Allowed)
}

func (s *K8sSuite) TestParseNetworkPolicyNoIngress(c *C) {
	netPolicy := &v1beta1.NetworkPolicy{
		Spec: v1beta1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"foo1": "bar1",
					"foo2": "bar2",
				},
			},
		},
	}

	rules, err := ParseNetworkPolicy(netPolicy)
	c.Assert(err, IsNil)
	c.Assert(len(rules), Equals, 1)
}
