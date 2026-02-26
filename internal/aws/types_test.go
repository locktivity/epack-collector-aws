package aws

import "testing"

func TestCredentialReportUserHelpers(t *testing.T) {
	root := CredentialReportUser{
		User:             "<root_account>",
		PasswordEnabled:  true,
		AccessKey1Active: true,
	}
	if !root.IsRootUser() {
		t.Fatalf("expected IsRootUser=true")
	}
	if !root.HasConsoleAccess() {
		t.Fatalf("expected HasConsoleAccess=true")
	}
	if !root.HasAccessKeys() {
		t.Fatalf("expected HasAccessKeys=true")
	}

	user := CredentialReportUser{
		User:             "alice",
		PasswordEnabled:  false,
		AccessKey1Active: false,
		AccessKey2Active: false,
	}
	if user.IsRootUser() {
		t.Fatalf("expected IsRootUser=false for IAM user")
	}
	if user.HasConsoleAccess() {
		t.Fatalf("expected HasConsoleAccess=false")
	}
	if user.HasAccessKeys() {
		t.Fatalf("expected HasAccessKeys=false")
	}
}

func TestSecurityGroupRuleHelpers(t *testing.T) {
	openWorldSSH := SecurityGroupRule{
		Protocol:   "tcp",
		FromPort:   22,
		ToPort:     22,
		CIDRBlocks: []string{"0.0.0.0/0"},
	}
	if !openWorldSSH.IsOpenToWorld() {
		t.Fatalf("expected IsOpenToWorld=true")
	}
	if !openWorldSSH.IsSSH() {
		t.Fatalf("expected IsSSH=true")
	}
	if openWorldSSH.IsRDP() {
		t.Fatalf("expected IsRDP=false")
	}
	if openWorldSSH.IsAllPorts() {
		t.Fatalf("expected IsAllPorts=false")
	}

	allPorts := SecurityGroupRule{
		Protocol: "-1",
		FromPort: -1,
		ToPort:   -1,
	}
	if !allPorts.IsAllPorts() {
		t.Fatalf("expected IsAllPorts=true for protocol -1")
	}
}
