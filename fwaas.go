package main

import (
	"fmt"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/fwaas_v2/groups"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/fwaas_v2/policies"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/fwaas_v2/rules"
)

func getFWRules(n *gophercloud.ServiceClient) []rules.Rule {
	fwRulesListOpts := rules.ListOpts{
		TenantID: "tenantmutantninjaturtles",
	}
	allFWRulesPages, err := rules.List(n, fwRulesListOpts).AllPages()
	if err != nil {
		panic(err)
	}
	allFWRules, err := rules.ExtractRules(allFWRulesPages)
	if err != nil {
		panic(err)
	}

	return allFWRules
}

func getFWPolicies(n *gophercloud.ServiceClient) []policies.Policy {
	fwPoliciesListOpts := policies.ListOpts{
		TenantID: "tenantmutantninjaturtles",
	}
	allFWPoliciesPages, err := policies.List(n, fwPoliciesListOpts).AllPages()
	if err != nil {
		panic(err)
	}
	allFWPolicies, err := policies.ExtractPolicies(allFWPoliciesPages)
	if err != nil {
		panic(err)
	}

	return allFWPolicies
}

func getFWGroups(n *gophercloud.ServiceClient) []groups.Group {
	fwGroupListOpts := groups.ListOpts{
		TenantID: "tenantmutantninjaturtles",
	}
	allFWGroupsPages, err := groups.List(n, fwGroupListOpts).AllPages()
	if err != nil {
		panic(err)
	}
	allFWGroups, err := groups.ExtractGroups(allFWGroupsPages)
	if err != nil {
		panic(err)
	}

	return allFWGroups
}

func main() {
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: "a_little_bit_of_url",
		Username:         "monica",
		Password:         "very_secret_plain_text",
		TenantID:         "tenantmutantninjaturtles",
		DomainName:       "do_main",
	}
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		fmt.Println(err)
		return
	}

	neutronClient, err := openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		Region: "ru-2",
	})
	// LISTING SECTION
	fmt.Println("")
	fmt.Println("*** LIST FIREWALL GROUPS:")
	for _, group := range getFWGroups(neutronClient) {
		fmt.Println(group.Name, group.ID)
	}
	fmt.Println("")
	fmt.Println("*** LIST FIREWALL POLICIES:")
	for _, policy := range getFWPolicies(neutronClient) {
		fmt.Println(policy.Name, policy.ID)
	}
	fmt.Println("")
	fmt.Println("*** LIST FIREWALL RULES:")
	for _, rule := range getFWRules(neutronClient) {
		fmt.Println(rule.Name, rule.ID)
	}

	// CREATION SECTION
	// RULE
	fmt.Println("")
	fmt.Println("*** CREATE FIREWALL RULE.")
	fwRuleCreateOpts := rules.CreateOpts{
		Name:     "RuleCreatedFromGopherCloud",
		Protocol: "icmp",
		Action:   "allow",
	}
	newRule, err := rules.Create(neutronClient, fwRuleCreateOpts).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println("*** FIREWALL RULES:")
	for _, rule := range getFWRules(neutronClient) {
		fmt.Println(rule.Name, rule.ID)
	}
	// POLICY
	fmt.Println("")
	fmt.Println("*** CREATE FIREWALL POLICY.")
	addingRules := []string{newRule.ID}
	fwPolicyCreateOpts := policies.CreateOpts{
		Name:          "PolicyCreatedFromGopherCloud",
		FirewallRules: addingRules,
	}
	newPolicy, err := policies.Create(neutronClient, fwPolicyCreateOpts).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println("*** FIREWALL POLICIES:")
	for _, policy := range getFWPolicies(neutronClient) {
		fmt.Println(policy.Name, policy.ID)
	}
	// GROUP
	fmt.Println("")
	fmt.Println("*** CREATE FIREWALL GROUP.")
	fwGroupCreateOpts := groups.CreateOpts{
		Name: "GroupCreatedFromGopherCloud",
	}
	newGroup, err := groups.Create(neutronClient, fwGroupCreateOpts).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println("*** FIREWALL GROUPS:")
	for _, group := range getFWGroups(neutronClient) {
		fmt.Println(group.Name, group.ID)
	}

	// GETTING SECTION
	// RULE
	fmt.Println("")
	fmt.Println("*** GET FIREWALL RULE:")
	newRuleGet, err := rules.Get(neutronClient, newRule.ID).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println(newRuleGet.Name, newRuleGet.ID)
	// POLICY
	fmt.Println("")
	fmt.Println("*** GET FIREWALL POLICY:")
	newPolicyGet, err := policies.Get(neutronClient, newPolicy.ID).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println(newPolicyGet.Name, newPolicyGet.ID)
	// GROUP
	fmt.Println("")
	fmt.Println("*** GET FIREWALL GROUP:")
	newGroupGet, err := groups.Get(neutronClient, newGroup.ID).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println(newGroupGet.Name, newGroupGet.ID)

	// INSERT RULE SECTION
	fmt.Println("")
	fmt.Println("*** FIREWALL RULE INSERT INTO POLICY.")
	fwInsertingRuleCreateOpts := rules.CreateOpts{
		Name:     "InsertingRuleCreatedFromGopherCloud",
		Protocol: "icmp",
		Action:   "deny",
	}
	newInsertingRule, err := rules.Create(neutronClient, fwInsertingRuleCreateOpts).Extract()
	if err != nil {
		panic(err)
	}
	insertRuleIntoPolicyListOpts := policies.InsertRuleOpts{
		ID:           newInsertingRule.ID,
		InsertBefore: newRule.ID,
	}
	insertRuleIntoPolicy, err := policies.InsertRule(neutronClient, newPolicy.ID, insertRuleIntoPolicyListOpts).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println(insertRuleIntoPolicy.Rules, insertRuleIntoPolicy.ID)
	// REMOVE RULE SECTION
	fmt.Println("")
	fmt.Println("*** FIREWALL RULE REMOVE FROM POLICY.")
	removeRuleIntoPolicy, err := policies.RemoveRule(neutronClient, newPolicy.ID, newInsertingRule.ID).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println(removeRuleIntoPolicy.Rules, removeRuleIntoPolicy.ID)
	err = rules.Delete(neutronClient, newInsertingRule.ID).ExtractErr()
	if err != nil {
		panic(err)
	}

	// UPDATING SECTION
	// GROUP
	fmt.Println("")
	fmt.Println("*** UPDATE FIREWALL GROUP:")
	newGroupName := "UpdatedGroupCreatedFromGopherCloud"
	newGroupUpdateOpts := groups.UpdateOpts{
		Name: &newGroupName,
	}
	newGroupUpdate, err := groups.Update(neutronClient, newGroup.ID, newGroupUpdateOpts).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println(newGroupUpdate.Name, newGroupUpdate.ID)
	// POLICY
	fmt.Println("")
	fmt.Println("*** UPDATE FIREWALL POLICY:")
	newPolicyName := "UpdatedPolicyCreatedFromGopherCloud"
	newPolicyUpdateOpts := policies.UpdateOpts{
		Name: &newPolicyName,
	}
	newPolicyUpdate, err := policies.Update(neutronClient, newPolicy.ID, newPolicyUpdateOpts).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println(newPolicyUpdate.Name, newPolicyUpdate.ID)
	// RULE
	fmt.Println("")
	fmt.Println("*** UPDATE FIREWALL RULE:")
	newRuleName := "UpdatedRuleCreatedFromGopherCloud"
	newRuleUpdateOpts := rules.UpdateOpts{
		Name: &newRuleName,
	}
	newRuleUpdate, err := rules.Update(neutronClient, newRule.ID, newRuleUpdateOpts).Extract()
	if err != nil {
		panic(err)
	}
	fmt.Println(newRuleUpdate.Name, newRuleUpdate.ID)

	// DELETING SECTION
	// GROUP
	fmt.Println("")
	fmt.Println("*** DELETE FIREWALL GROUP.")
	err = groups.Delete(neutronClient, newGroup.ID).ExtractErr()
	if err != nil {
		panic(err)
	}
	fmt.Println("*** FIREWALL GROUP:")
	for _, group := range getFWGroups(neutronClient) {
		fmt.Println(group.Name, group.ID)
	}
	// POLICY
	fmt.Println("")
	fmt.Println("*** DELETE FIREWALL POLICY.")
	err = policies.Delete(neutronClient, newPolicy.ID).ExtractErr()
	if err != nil {
		panic(err)
	}
	fmt.Println("*** FIREWALL POLICY:")
	for _, policy := range getFWPolicies(neutronClient) {
		fmt.Println(policy.Name, policy.ID)
	}
	// RULE
	fmt.Println("")
	fmt.Println("*** DELETE FIREWALL RULE.")
	err = rules.Delete(neutronClient, newRule.ID).ExtractErr()
	if err != nil {
		panic(err)
	}
	fmt.Println("*** FIREWALL RULES:")
	for _, rule := range getFWRules(neutronClient) {
		fmt.Println(rule.Name, rule.ID)
	}
}
