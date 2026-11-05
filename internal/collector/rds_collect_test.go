package collector

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-aws/internal/aws"
	"github.com/locktivity/epack/componentsdk"
)

// queryTransport answers the AWS Query and EC2 calls the RDS surface makes,
// from a table of results keyed by "service:Action". A call that names a
// parameter group is looked up first by "service:Action:group".
type queryTransport struct {
	t       *testing.T
	results map[string]string
}

func (a *queryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	form, _ := url.ParseQuery(string(body))
	action := form.Get("Action")
	service := strings.SplitN(req.URL.Host, ".", 2)[0]

	key := service + ":" + action
	result, ok := a.results[key+":"+form.Get("DBParameterGroupName")]
	if !ok {
		result, ok = a.results[key]
	}
	if !ok {
		a.t.Errorf("unexpected call %s (form %v)", key, form)
		return &http.Response{StatusCode: 500, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader("<Response/>")), Request: req}, nil
	}

	var xml string
	if service == "ec2" {
		xml = "<" + action + "Response xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><requestId>kit</requestId>" + result + "</" + action + "Response>"
	} else {
		xml = "<" + action + "Response xmlns=\"https://rds.amazonaws.com/doc/\"><" + action + "Result>" + result + "</" + action + "Result>" +
			"<ResponseMetadata><RequestId>kit</RequestId></ResponseMetadata></" + action + "Response>"
	}
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/xml"}},
		Body:       io.NopCloser(strings.NewReader(xml)),
		Request:    req,
	}, nil
}

// runRDS runs the RDS surface for one region at audit level against the
// canned results and returns what it collected.
func runRDS(t *testing.T, results map[string]string) *rdsMetricsWithCounts {
	t.Helper()
	isolateAWSEnvironment(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDKITEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "kit-secret")
	t.Setenv("AWS_REGION", "us-east-1")

	client, err := aws.NewClient(context.Background(), aws.Options{HTTPClient: &http.Client{Transport: &queryTransport{t: t, results: results}}})
	if err != nil {
		t.Fatalf("creating client: %v", err)
	}
	got, err := newTestCollector(Config{}).collectRDSMetrics(context.Background(), client, "us-east-1", componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("collecting RDS metrics: %v", err)
	}
	got.finalize()
	return got
}

const rdsEventsTopicARN = "arn:aws:sns:us-east-1:111122223333:rds-events"

func rdsEventSubscription(status string) map[string]string {
	return map[string]string{
		"rds:DescribeDBInstances": "<DBInstances/>",
		"rds:DescribeDBClusters":  "<DBClusters/>",
		"rds:DescribeEventSubscriptions": "<EventSubscriptionsList><EventSubscription>" +
			"<CustSubscriptionId>backups</CustSubscriptionId><Enabled>true</Enabled><SourceType>db-instance</SourceType>" +
			"<EventCategoriesList><EventCategory>backup</EventCategory></EventCategoriesList>" +
			"<SnsTopicArn>" + rdsEventsTopicARN + "</SnsTopicArn><Status>" + status + "</Status></EventSubscription></EventSubscriptionsList>",
		"sns:ListSubscriptionsByTopic": "<Subscriptions><member><SubscriptionArn>" + rdsEventsTopicARN + ":6f1c2a3b-0000-4000-8000-000000000001</SubscriptionArn>" +
			"<Owner>111122223333</Owner><Protocol>email</Protocol><Endpoint>oncall@example.test</Endpoint><TopicArn>" + rdsEventsTopicARN + "</TopicArn></member></Subscriptions>",
	}
}

// A subscription with status no-permission cannot post to its topic, so it
// carries no backup failure although Enabled stays true.
func TestCollectRDSMetrics_NoPermissionSubscriptionCarriesNothing(t *testing.T) {
	got := runRDS(t, rdsEventSubscription("no-permission"))

	if got.BackupFailureAlertingSubscriptionCount != 0 || got.BackupFailureAlertingReachingSubscriberCount != 0 {
		t.Errorf("covering = %d, reaching a subscriber = %d, want 0 and 0: a no-permission subscription cannot post to its topic",
			got.BackupFailureAlertingSubscriptionCount, got.BackupFailureAlertingReachingSubscriberCount)
	}
}

// The same subscription with status active reaches the topic's subscriber.
func TestCollectRDSMetrics_ActiveSubscriptionReachesASubscriber(t *testing.T) {
	got := runRDS(t, rdsEventSubscription("active"))

	if got.BackupFailureAlertingSubscriptionCount != 1 || got.BackupFailureAlertingReachingSubscriberCount != 1 {
		t.Errorf("covering = %d, reaching a subscriber = %d, want 1 and 1",
			got.BackupFailureAlertingSubscriptionCount, got.BackupFailureAlertingReachingSubscriberCount)
	}
}

func postgresInstance(clusterID string) string {
	cluster := ""
	if clusterID != "" {
		cluster = "<DBClusterIdentifier>" + clusterID + "</DBClusterIdentifier>"
	}
	return "<DBInstance><DBInstanceIdentifier>pg-1</DBInstanceIdentifier>" + cluster + "<Engine>postgres</Engine><EngineVersion>16.4</EngineVersion>" +
		"<StorageEncrypted>true</StorageEncrypted><BackupRetentionPeriod>14</BackupRetentionPeriod>" +
		"<DBParameterGroups><DBParameterGroup><DBParameterGroupName>default.postgres16</DBParameterGroupName><ParameterApplyStatus>in-sync</ParameterApplyStatus></DBParameterGroup></DBParameterGroups>" +
		"<EnabledCloudwatchLogsExports><member>postgresql</member></EnabledCloudwatchLogsExports></DBInstance>"
}

func postgresResults(instance string) map[string]string {
	return map[string]string{
		"rds:DescribeDBInstances":        "<DBInstances>" + instance + "</DBInstances>",
		"rds:DescribeDBClusters":         "<DBClusters/>",
		"rds:DescribeEventSubscriptions": "<EventSubscriptionsList/>",
		// The engine-default group, which logs nothing. A Multi-AZ DB
		// cluster keeps its settings in its DB cluster parameter group.
		"rds:DescribeDBParameters": "<Parameters>" +
			"<Parameter><ParameterName>shared_preload_libraries</ParameterName><ParameterValue>pg_stat_statements</ParameterValue></Parameter>" +
			"<Parameter><ParameterName>log_statement</ParameterName><ParameterValue>none</ParameterValue></Parameter>" +
			"</Parameters>",
	}
}

// A member of a Multi-AZ DB cluster takes its settings from the cluster
// parameter group, which is not read, so its data-change logging is not
// classified.
func TestCollectRDSMetrics_ClusterMemberDMLLoggingIsNotClassified(t *testing.T) {
	got := runRDS(t, postgresResults(postgresInstance("pg-multi-az-cluster")))

	if got.DMLLoggingNotConfiguredCount != 0 {
		t.Errorf("dml_logging_not_configured_count = %d, want 0: the instance's own parameter group does not hold its cluster's logging settings",
			got.DMLLoggingNotConfiguredCount)
	}
	if len(got.Instances) != 1 {
		t.Fatalf("instances = %d, want 1", len(got.Instances))
	}
	if got.Instances[0].DMLLogging != dmlLoggingNotClassified || got.DMLLoggingNotClassifiedCount != 1 {
		t.Errorf("instance dml_logging = %q, not classified count = %d; want %q and 1 for a cluster member", got.Instances[0].DMLLogging, got.DMLLoggingNotClassifiedCount, dmlLoggingNotClassified)
	}
}

// The same instance outside a cluster, on the same default group, is not
// configured.
func TestCollectRDSMetrics_StandaloneInstanceDMLLoggingNotConfigured(t *testing.T) {
	got := runRDS(t, postgresResults(postgresInstance("")))

	if got.DMLLoggingNotConfiguredCount != 1 || len(got.Instances) != 1 || got.Instances[0].DMLLogging != dmlLoggingNotConfigured {
		t.Errorf("not_configured count = %d, want 1 for a standalone instance on the default group", got.DMLLoggingNotConfiguredCount)
	}
}

func ingressResults(permission string) map[string]string {
	return map[string]string{
		"rds:DescribeDBInstances": "<DBInstances><DBInstance><DBInstanceIdentifier>pg-1</DBInstanceIdentifier><Engine>mysql</Engine>" +
			"<Endpoint><Port>5432</Port></Endpoint>" +
			"<VpcSecurityGroups><VpcSecurityGroupMembership><VpcSecurityGroupId>sg-0db</VpcSecurityGroupId><Status>active</Status></VpcSecurityGroupMembership></VpcSecurityGroups>" +
			"</DBInstance></DBInstances>",
		"rds:DescribeDBClusters":         "<DBClusters/>",
		"rds:DescribeEventSubscriptions": "<EventSubscriptionsList/>",
		"ec2:DescribeSecurityGroups": "<securityGroupInfo><item><groupId>sg-0db</groupId><groupName>database</groupName><groupDescription>database</groupDescription>" +
			"<vpcId>vpc-0kit</vpcId><ipPermissions>" + permission + "</ipPermissions></item></securityGroupInfo>",
	}
}

// prefixListIngress is the database-port setup of ingressResults with a rule
// that allows a managed prefix list holding entries.
func prefixListIngress(entries string) map[string]string {
	results := ingressResults(
		"<item><ipProtocol>tcp</ipProtocol><fromPort>5432</fromPort><toPort>5432</toPort>" +
			"<prefixListIds><item><prefixListId>pl-0anywhere</prefixListId></item></prefixListIds></item>")
	results["ec2:GetManagedPrefixListEntries"] = "<entrySet>" + entries + "</entrySet>"
	return results
}

// A rule that allows a managed prefix list on the database port allows
// something, so the prefix list is one of the instance's sources.
func TestCollectRDSMetrics_PrefixListRuleIsAnIngressSource(t *testing.T) {
	got := runRDS(t, prefixListIngress("<item><cidr>10.20.0.0/16</cidr></item>"))

	if len(got.Instances) != 1 {
		t.Fatalf("instances = %d, want 1", len(got.Instances))
	}
	row := got.Instances[0]
	if row.DBPortIngressEvaluated == nil || !*row.DBPortIngressEvaluated || len(row.DBPortIngressSources) != 1 || row.DBPortIngressSources[0] != "pl-0anywhere" {
		t.Errorf("evaluated = %v, sources = %v, want evaluated with [pl-0anywhere]", row.DBPortIngressEvaluated, row.DBPortIngressSources)
	}
}

// A rule with a CIDR source is listed.
func TestCollectRDSMetrics_CIDRRuleIsAnIngressSource(t *testing.T) {
	got := runRDS(t, ingressResults(
		"<item><ipProtocol>tcp</ipProtocol><fromPort>5432</fromPort><toPort>5432</toPort>"+
			"<ipRanges><item><cidrIp>10.0.0.0/16</cidrIp></item></ipRanges></item>"))

	if len(got.Instances) != 1 {
		t.Fatalf("instances = %d, want 1", len(got.Instances))
	}
	row := got.Instances[0]
	if row.DBPortIngressEvaluated == nil || !*row.DBPortIngressEvaluated || len(row.DBPortIngressSources) != 1 || row.DBPortIngressSources[0] != "10.0.0.0/16" {
		t.Errorf("evaluated = %v, sources = %v, want evaluated with [10.0.0.0/16]", row.DBPortIngressEvaluated, row.DBPortIngressSources)
	}
}

// auroraResults lists one Multi-AZ, deletion-protected Aurora cluster with
// two instances, which report MultiAZ and DeletionProtection false.
func auroraResults() map[string]string {
	member := func(id string) string {
		return "<DBInstance><DBInstanceIdentifier>" + id + "</DBInstanceIdentifier><DBClusterIdentifier>aurora-prod</DBClusterIdentifier>" +
			"<Engine>aurora-postgresql</Engine><StorageEncrypted>true</StorageEncrypted><BackupRetentionPeriod>14</BackupRetentionPeriod>" +
			"<MultiAZ>false</MultiAZ><DeletionProtection>false</DeletionProtection></DBInstance>"
	}
	return map[string]string{
		"rds:DescribeDBInstances": "<DBInstances>" + member("aurora-1") + member("aurora-2") + "</DBInstances>",
		"rds:DescribeDBClusters": "<DBClusters><DBCluster><DBClusterIdentifier>aurora-prod</DBClusterIdentifier><Engine>aurora-postgresql</Engine>" +
			"<StorageEncrypted>true</StorageEncrypted><DeletionProtection>true</DeletionProtection><MultiAZ>true</MultiAZ>" +
			"<BackupRetentionPeriod>14</BackupRetentionPeriod></DBCluster></DBClusters>",
		"rds:DescribeEventSubscriptions": "<EventSubscriptionsList/>",
	}
}

// Multi-AZ, deletion protection, encryption and backup retention do not apply
// to an Aurora instance, so an Aurora cluster and its instances are one
// database with the cluster's settings.
func TestCollectRDSMetrics_AuroraClusterIsOneDatabase(t *testing.T) {
	got := runRDS(t, auroraResults())

	if got.DatabaseCount != 1 || got.InstanceCount != 2 {
		t.Errorf("database_count = %d, instance_count = %d, want 1 and 2", got.DatabaseCount, got.InstanceCount)
	}
	for name, pct := range map[string]*int{"multi_az_enabled": got.MultiAZEnabled, "deletion_protection": got.DeletionProtection,
		"encrypted_at_rest": got.EncryptedAtRest, "backup_retention_adequate": got.BackupRetentionAdequate} {
		if !pctIs(pct, 100) {
			t.Errorf("%s = %s, want 100 for the cluster's settings", name, showPct(pct))
		}
	}
	if len(got.Instances) != 2 {
		t.Errorf("instances = %d rows, want both Aurora instances listed", len(got.Instances))
	}
}

// A standalone Multi-AZ, deletion-protected instance counts as a database
// with its own settings.
func TestCollectRDSMetrics_StandaloneInstanceIsADatabase(t *testing.T) {
	got := runRDS(t, map[string]string{
		"rds:DescribeDBInstances": "<DBInstances><DBInstance><DBInstanceIdentifier>mysql-1</DBInstanceIdentifier><Engine>mysql</Engine>" +
			"<StorageEncrypted>true</StorageEncrypted><BackupRetentionPeriod>14</BackupRetentionPeriod><MultiAZ>true</MultiAZ>" +
			"<DeletionProtection>true</DeletionProtection></DBInstance></DBInstances>",
		"rds:DescribeDBClusters":         "<DBClusters/>",
		"rds:DescribeEventSubscriptions": "<EventSubscriptionsList/>",
	})

	if got.DatabaseCount != 1 || !pctIs(got.MultiAZEnabled, 100) || !pctIs(got.DeletionProtection, 100) {
		t.Errorf("database_count = %d, multi_az_enabled = %s, deletion_protection = %s; want 1, 100 and 100",
			got.DatabaseCount, showPct(got.MultiAZEnabled), showPct(got.DeletionProtection))
	}
}

// The normalized database counts treat an Aurora cluster and its instances
// as one database that runs across availability zones.
func TestNormalizedDatabase_AuroraClusterIsOneDatabase(t *testing.T) {
	got := runRDS(t, auroraResults())
	got.RegionsEvaluatedCount = 1
	db := normalizedDatabase(got.RDSMetrics, true)

	if !pctIs(db.DatabaseCount, 1) || !pctIs(db.MultiAZDatabaseCount, 1) || db.MultiAZPct.Value == nil || *db.MultiAZPct.Value != 100 {
		t.Errorf("database_count = %s, multi_az_database_count = %s, multi_az_pct = %v; want 1, 1 and 100",
			showPct(db.DatabaseCount), showPct(db.MultiAZDatabaseCount), db.MultiAZPct.Value)
	}
}

// A rule that allows a prefix list allows every CIDR block in it, so a list
// holding 0.0.0.0/0 opens the database port to the internet.
func TestCollectRDSMetrics_PrefixListOpensDBPort(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
		open  bool
	}{
		{"any IPv4 address", "0.0.0.0/0", true},
		{"any IPv6 address", "::/0", true},
		{"private range", "10.20.0.0/16", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runRDS(t, prefixListIngress("<item><cidr>"+tc.entry+"</cidr></item>"))

			if len(got.Instances) != 1 || got.Instances[0].DBPortOpenToInternet == nil {
				t.Fatalf("rows = %+v, want one instance with db_port_open_to_internet set", got.Instances)
			}
			wantCount := map[bool]int{true: 1, false: 0}[tc.open]
			if *got.Instances[0].DBPortOpenToInternet != tc.open || got.DBPortOpenToInternetCount != wantCount {
				t.Errorf("db_port_open_to_internet = %v, db_port_open_to_internet_count = %d, want %v and %d",
					*got.Instances[0].DBPortOpenToInternet, got.DBPortOpenToInternetCount, tc.open, wantCount)
			}
		})
	}
}

// clusterMemberInstance is one DB instance of clusterID. The cluster holds
// its Multi-AZ and deletion protection settings, so the instance reports
// them false.
func clusterMemberInstance(id, clusterID, engine string) string {
	return "<DBInstance><DBInstanceIdentifier>" + id + "</DBInstanceIdentifier><DBClusterIdentifier>" + clusterID + "</DBClusterIdentifier>" +
		"<Engine>" + engine + "</Engine><StorageEncrypted>true</StorageEncrypted><BackupRetentionPeriod>14</BackupRetentionPeriod>" +
		"<MultiAZ>false</MultiAZ><DeletionProtection>false</DeletionProtection></DBInstance>"
}

func clusterWithMembers(clusterID, engine string, members ...string) map[string]string {
	var instances strings.Builder
	for _, m := range members {
		instances.WriteString(clusterMemberInstance(m, clusterID, engine))
	}
	return map[string]string{
		"rds:DescribeDBInstances": "<DBInstances>" + instances.String() + "</DBInstances>",
		"rds:DescribeDBClusters": "<DBClusters><DBCluster><DBClusterIdentifier>" + clusterID + "</DBClusterIdentifier><Engine>" + engine + "</Engine>" +
			"<StorageEncrypted>true</StorageEncrypted><DeletionProtection>true</DeletionProtection><MultiAZ>true</MultiAZ>" +
			"<BackupRetentionPeriod>14</BackupRetentionPeriod></DBCluster></DBClusters>",
		"rds:DescribeEventSubscriptions": "<EventSubscriptionsList/>",
	}
}

// The instances of a DB cluster are managed through the cluster, so a
// cluster and its instances count as one database. This holds for Aurora, a
// Multi-AZ DB cluster, DocumentDB and Neptune.
func TestCollectRDSMetrics_ClusterAndItsInstancesAreOneDatabase(t *testing.T) {
	for _, tc := range []struct {
		engine  string
		members []string
	}{
		{"aurora-postgresql", []string{"aurora-1", "aurora-2"}},
		{"postgres", []string{"multi-az-1", "multi-az-2", "multi-az-3"}},
		{"docdb", []string{"docdb-1", "docdb-2"}},
		{"neptune", []string{"neptune-1", "neptune-2"}},
	} {
		t.Run(tc.engine, func(t *testing.T) {
			got := runRDS(t, clusterWithMembers("cluster-1", tc.engine, tc.members...))

			if got.DatabaseCount != 1 || got.InstanceCount != len(tc.members) {
				t.Errorf("database_count = %d, instance_count = %d, want 1 and %d", got.DatabaseCount, got.InstanceCount, len(tc.members))
			}
			if !pctIs(got.MultiAZEnabled, 100) || got.MultiAZEnabledDatabaseCount != 1 {
				t.Errorf("multi_az_enabled = %s, multi_az_enabled_database_count = %d, want 100 and 1", showPct(got.MultiAZEnabled), got.MultiAZEnabledDatabaseCount)
			}
		})
	}
}

// encryptionResults answers the RDS calls for a region whose one database is
// an Aurora cluster or a standalone instance, with the StorageEncrypted flag
// and StorageEncryptionType given.
func encryptionResults(cluster bool, encrypted, encryptionType string) map[string]string {
	storage := "<StorageEncrypted>" + encrypted + "</StorageEncrypted><StorageEncryptionType>" + encryptionType + "</StorageEncryptionType>" +
		"<BackupRetentionPeriod>14</BackupRetentionPeriod>"
	if cluster {
		return map[string]string{
			"rds:DescribeDBInstances": "<DBInstances/>",
			"rds:DescribeDBClusters": "<DBClusters><DBCluster><DBClusterIdentifier>northwind-aurora</DBClusterIdentifier><Engine>aurora-postgresql</Engine>" +
				"<EngineVersion>16.4</EngineVersion>" + storage + "</DBCluster></DBClusters>",
			"rds:DescribeEventSubscriptions": "<EventSubscriptionsList/>",
		}
	}
	return map[string]string{
		"rds:DescribeDBInstances": "<DBInstances><DBInstance><DBInstanceIdentifier>mysql-1</DBInstanceIdentifier><Engine>mysql</Engine>" +
			storage + "</DBInstance></DBInstances>",
		"rds:DescribeDBClusters":         "<DBClusters/>",
		"rds:DescribeEventSubscriptions": "<EventSubscriptionsList/>",
	}
}

// Storage encrypted with an AWS owned key has StorageEncrypted false and
// StorageEncryptionType sse-rds. It is encrypted at rest, for a cluster and
// for a standalone instance alike.
func TestCollectRDSMetrics_AWSOwnedKeyIsEncryptedAtRest(t *testing.T) {
	for _, tc := range []struct {
		name           string
		encrypted      string
		encryptionType string
		want           bool
	}{
		{"AWS owned key", "false", "sse-rds", true},
		{"customer managed key", "true", "sse-kms", true},
		{"not encrypted", "false", "none", false},
	} {
		for _, cluster := range []bool{true, false} {
			kind := "instance"
			if cluster {
				kind = "cluster"
			}
			t.Run(tc.name+" "+kind, func(t *testing.T) {
				got := runRDS(t, encryptionResults(cluster, tc.encrypted, tc.encryptionType))
				got.RegionsEvaluatedCount = 1
				db := normalizedDatabase(got.RDSMetrics, true)

				wantCount, wantPct := 0, 0.0
				if tc.want {
					wantCount, wantPct = 1, 100
				}
				if !pctIs(db.DatabaseCount, 1) || !pctIs(db.EncryptedDatabaseCount, wantCount) {
					t.Errorf("database_count = %s, encrypted_database_count = %s, want 1 and %d",
						showPct(db.DatabaseCount), showPct(db.EncryptedDatabaseCount), wantCount)
				}
				if db.EncryptionPct.Value == nil || *db.EncryptionPct.Value != wantPct {
					t.Errorf("encryption_pct = %v, want %v", db.EncryptionPct.Value, wantPct)
				}
				rowEncrypted := false
				switch {
				case cluster && len(got.Clusters) == 1:
					rowEncrypted = got.Clusters[0].StorageEncrypted
				case !cluster && len(got.Instances) == 1:
					rowEncrypted = got.Instances[0].StorageEncrypted
				default:
					t.Fatalf("clusters = %d, instances = %d, want the one %s", len(got.Clusters), len(got.Instances), kind)
				}
				if rowEncrypted != tc.want {
					t.Errorf("storage_encrypted = %t, want %t", rowEncrypted, tc.want)
				}
			})
		}
	}
}
