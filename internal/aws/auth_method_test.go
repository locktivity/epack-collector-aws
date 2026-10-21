package aws

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/locktivity/epack/componentsdk"
)

// TestAuthMethodOfTheDefaultChain loads the SDK's default configuration from
// each kind of source and checks the sign-in method read from the sources
// the SDK records.
func TestAuthMethodOfTheDefaultChain(t *testing.T) {
	cases := []struct {
		name   string
		env    map[string]string
		config string
		want   string
	}{
		{
			name: "access keys in the environment",
			env:  map[string]string{"AWS_ACCESS_KEY_ID": "kit-access-key-id", "AWS_SECRET_ACCESS_KEY": "kit-secret"},
			want: componentsdk.AuthAccessKey,
		},
		{
			name: "web identity token in the environment",
			env:  map[string]string{"AWS_ROLE_ARN": "arn:aws:iam::111122223333:role/epack-collector", "AWS_WEB_IDENTITY_TOKEN_FILE": "token"},
			want: componentsdk.AuthWorkloadIdentity,
		},
		{
			name:   "access keys in a profile",
			config: "[default]\naws_access_key_id = kit-access-key-id\naws_secret_access_key = kit-secret\n",
			want:   componentsdk.AuthAccessKey,
		},
		{
			name:   "role assumed with a profile's access keys",
			config: "[default]\nrole_arn = arn:aws:iam::111122223333:role/epack-collector\nsource_profile = keys\n\n[profile keys]\naws_access_key_id = kit-access-key-id\naws_secret_access_key = kit-secret\n",
			want:   componentsdk.AuthAccessKey,
		},
		{
			name:   "credential process",
			config: "[default]\ncredential_process = /bin/false\n",
			want:   "",
		},
		{name: "instance role", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, key := range []string{
				"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
				"AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME", "AWS_WEB_IDENTITY_TOKEN_FILE",
				"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
			} {
				t.Setenv(key, "")
			}
			configFile := filepath.Join(dir, "config")
			if err := os.WriteFile(configFile, []byte(tc.config), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("AWS_CONFIG_FILE", configFile)
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
			t.Setenv("AWS_REGION", DefaultRegionAWS)
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
			for k, v := range tc.env {
				if k == "AWS_WEB_IDENTITY_TOKEN_FILE" {
					v = filepath.Join(dir, v)
				}
				t.Setenv(k, v)
			}
			cfg, err := config.LoadDefaultConfig(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got := authMethodOf(cfg.Credentials); got != tc.want {
				t.Errorf("authMethodOf() = %q, want %q", got, tc.want)
			}
		})
	}
}
