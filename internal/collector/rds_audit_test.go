package collector

import (
	"errors"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
)

func pgInstance(applyStatus string, exports ...string) aws.DBInstance {
	return aws.DBInstance{
		DBInstanceIdentifier: "api-db",
		Engine:               "postgres",
		ParameterGroupName:   "custom-pg16",
		ParameterApplyStatus: applyStatus,
		LogExports:           exports,
	}
}

func TestClassifyDMLLogging(t *testing.T) {
	tests := []struct {
		name     string
		instance aws.DBInstance
		params   map[string]string
		err      error
		want     string
	}{
		{
			name:     "pgaudit write logging, in sync, exported",
			instance: pgInstance("in-sync", "postgresql"),
			params:   map[string]string{"shared_preload_libraries": "pg_stat_statements,pgaudit", "pgaudit.log": "ddl, write"},
			want:     dmlLoggingConfigured,
		},
		{
			name:     "log_statement mod alone is enough",
			instance: pgInstance("in-sync", "postgresql"),
			params:   map[string]string{"log_statement": "mod"},
			want:     dmlLoggingConfigured,
		},
		{
			name:     "configured but logs never leave the instance",
			instance: pgInstance("in-sync"),
			params:   map[string]string{"log_statement": "all"},
			want:     dmlLoggingNotExported,
		},
		{
			// The pack must not certify logging that is not happening: desired
			// values in a pending-reboot group are not in force.
			name:     "pending reboot is not configured",
			instance: pgInstance("pending-reboot", "postgresql"),
			params:   map[string]string{"log_statement": "mod"},
			want:     dmlLoggingPending,
		},
		{
			name:     "pgaudit loaded but only DDL is audited",
			instance: pgInstance("in-sync", "postgresql"),
			params:   map[string]string{"shared_preload_libraries": "pgaudit", "pgaudit.log": "ddl, role"},
			want:     dmlLoggingNotConfigured,
		},
		{
			name:     "unreadable parameters are unknown, never absent",
			instance: pgInstance("in-sync", "postgresql"),
			err:      errors.New("AccessDenied"),
			want:     dmlLoggingUnknown,
		},
		{
			name:     "mysql is not classified rather than not logging",
			instance: aws.DBInstance{DBInstanceIdentifier: "legacy", Engine: "mysql"},
			want:     dmlLoggingNotClassified,
		},
		{
			name:     "aurora postgres keeps these in cluster groups",
			instance: aws.DBInstance{DBInstanceIdentifier: "aurora", Engine: "aurora-postgresql"},
			want:     dmlLoggingNotClassified,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyDMLLogging(tt.instance, tt.params, tt.err); got != tt.want {
				t.Fatalf("classifyDMLLogging() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSubscriptionCoversBackupFailures(t *testing.T) {
	tests := []struct {
		name string
		sub  aws.RDSEventSubscription
		want bool
	}{
		{
			// The common real-world configuration: subscribe to everything.
			// Empty categories cover all categories, so this must count.
			name: "empty categories cover everything",
			sub:  aws.RDSEventSubscription{Enabled: true},
			want: true,
		},
		{
			name: "explicit backup category",
			sub:  aws.RDSEventSubscription{Enabled: true, SourceType: "db-instance", EventCategories: []string{"backup"}},
			want: true,
		},
		{
			name: "failure category also carries backup failures",
			sub:  aws.RDSEventSubscription{Enabled: true, SourceType: "db-instance", EventCategories: []string{"failure"}},
			want: true,
		},
		{
			name: "availability-only subscription does not",
			sub:  aws.RDSEventSubscription{Enabled: true, SourceType: "db-instance", EventCategories: []string{"availability"}},
			want: false,
		},
		{
			name: "disabled subscription covers nothing",
			sub:  aws.RDSEventSubscription{Enabled: false},
			want: false,
		},
		{
			name: "security-group source type is out of scope",
			sub:  aws.RDSEventSubscription{Enabled: true, SourceType: "db-security-group"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := subscriptionCoversBackupFailures(tt.sub); got != tt.want {
				t.Fatalf("subscriptionCoversBackupFailures() = %v, want %v", got, tt.want)
			}
		})
	}
}
