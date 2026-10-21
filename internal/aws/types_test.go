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

	// EC2 sends an all-traffic rule with no ports at all.
	allTraffic := SecurityGroupRule{Protocol: "-1", CIDRBlocks: []string{"0.0.0.0/0"}}
	if !allTraffic.IsSSH() || !allTraffic.IsRDP() {
		t.Fatalf("expected an all-traffic rule to cover SSH and RDP")
	}

	udpSSH := SecurityGroupRule{Protocol: "udp", FromPort: 22, ToPort: 22}
	if udpSSH.IsSSH() {
		t.Fatalf("expected IsSSH=false for UDP on port 22")
	}
}

func TestKMSKeyRotatable(t *testing.T) {
	cases := []struct {
		spec, origin string
		want         bool
	}{
		{"SYMMETRIC_DEFAULT", "AWS_KMS", true},
		{"SYMMETRIC_DEFAULT", "EXTERNAL", false},
		{"SYMMETRIC_DEFAULT", "AWS_CLOUDHSM", false},
		{"SYMMETRIC_DEFAULT", "EXTERNAL_KEY_STORE", false},
		{"RSA_2048", "AWS_KMS", false},
		{"HMAC_256", "AWS_KMS", false},
	}
	for _, tc := range cases {
		if got := (KMSKey{KeySpec: tc.spec, Origin: tc.origin}).Rotatable(); got != tc.want {
			t.Errorf("%s key from %s: Rotatable() = %t, want %t", tc.spec, tc.origin, got, tc.want)
		}
	}
}
