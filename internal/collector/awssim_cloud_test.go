package collector

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The cloud side of the simulator answers S3, the security groups,
// CloudTrail, RDS and KMS from the roster's storage, security groups and
// cloud block. Each resource is in its region extra's region, or the first
// region the run scans.

// simBucketURL is a bucket's virtual-hosted URL in region, as the SDK
// calls it, with query.
func simBucketURL(bucket, region, query string) string {
	return "https://" + bucket + ".s3." + region + ".amazonaws.com/?" + query
}

func (s *awsSim) keySource(source string) string { return s.r.Terms.KeySources[source] }

// keyARN is the ARN of the customer managed KMS key that encrypts the
// resource named key.
func (s *awsSim) keyARN(region, key string) string {
	return "arn:aws:kms:" + region + ":" + s.account.ID + ":key/" + simulate.UUID("kms", key)
}

// s3 answers the bucket listing and each bucket's location, public access
// block and default encryption. A bucket that refuses anonymous access
// blocks every kind of public access itself, unless its
// public_access_block extra is acls, which blocks public ACLs alone and
// leaves public policies to the account's block, as the sandbox's
// pab-combined bucket does. One that allows it turns every flag off, or
// has no block at all when the extra is absent. S3 encrypts every bucket,
// so a key source mapped to none answers as a bucket from before 2023 with
// no default encryption configured. The bucket's versioning, logging and
// policy are the recording's for a recorded bucket, and none for another.
func (s *awsSim) s3() {
	listResp, list := s.recorded("aws.s3.ListBuckets", nil)
	recorded := simItems(list, "ListAllMyBucketsResult", "Buckets", "Bucket")
	var buckets []any
	for _, st := range s.r.Storage {
		region := s.regionOf(st.Extra)
		b, _ := simPick(recorded, "Name", st.Key)
		b["Name"], b["BucketRegion"], b["BucketArn"] = st.Key, region, "arn:aws:s3:::"+st.Key
		buckets = append(buckets, b)
		s.bucket(st, region)
	}
	simFirst(list, "ListAllMyBucketsResult")["Buckets"] = simList("Bucket", buckets)
	s.add(listResp, list)
}

func (s *awsSim) bucket(st roster.Storage, region string) {
	r, body := s.recorded("aws.s3.GetBucketLocation", nil)
	r.URL = simBucketURL(st.Key, s.home(), "location=")
	location := simFirst(body, "LocationConstraint")
	delete(location, "#text")
	if region != "us-east-1" {
		location["#text"] = region
	}
	s.add(r, body)

	rendering := "all"
	if st.AnonymousAccess {
		rendering = "off"
	}
	simulate.Extra(st.Extra, "public_access_block", &rendering)
	if rendering == "absent" {
		s.add(s.s3Error("aws.s3.GetPublicAccessBlock", simBucketURL(st.Key, region, "publicAccessBlock="), st.Key,
			"NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found"))
	} else {
		r, body := s.recorded("aws.s3.GetPublicAccessBlock", func(r collectortest.Response) bool { return r.Status == http.StatusOK })
		r.URL = simBucketURL(st.Key, region, "publicAccessBlock=")
		block := simFirst(body, "PublicAccessBlockConfiguration")
		acls, policies := rendering == "all" || rendering == "acls", rendering == "all"
		block["BlockPublicAcls"], block["IgnorePublicAcls"] = strconv.FormatBool(acls), strconv.FormatBool(acls)
		block["BlockPublicPolicy"], block["RestrictPublicBuckets"] = strconv.FormatBool(policies), strconv.FormatBool(policies)
		s.add(r, body)
	}

	switch s.keySource(st.KeySource) {
	case roster.NoKey:
		s.add(s.s3Error("aws.s3.GetBucketEncryption", simBucketURL(st.Key, region, "encryption="), st.Key,
			"ServerSideEncryptionConfigurationNotFoundError", "The server side encryption configuration was not found"))
	default:
		r, body := s.recorded("aws.s3.GetBucketEncryption", nil)
		r.URL = simBucketURL(st.Key, region, "encryption=")
		rule := simFirst(body, "ServerSideEncryptionConfiguration", "Rule")
		byDefault := simFirst(rule, "ApplyServerSideEncryptionByDefault")
		if s.keySource(st.KeySource) == roster.CustomerKey {
			byDefault["SSEAlgorithm"], byDefault["KMSMasterKeyID"] = "aws:kms", s.keyARN(region, st.Key)
			rule["BucketKeyEnabled"] = "true"
		}
		s.add(r, body)
	}

	for _, setting := range []struct{ op, query string }{
		{"aws.s3.GetBucketVersioning", "versioning="},
		{"aws.s3.GetBucketLogging", "logging="},
		{"aws.s3.GetBucketPolicy", "policy="},
	} {
		url := simBucketURL(st.Key, region, setting.query)
		if slices.ContainsFunc(s.rec.responses, func(r collectortest.Response) bool { return r.Operation == setting.op && s.rewrite(r).URL == url }) {
			continue
		}
		if setting.op == "aws.s3.GetBucketPolicy" {
			s.add(s.s3Error(setting.op, url, st.Key, "NoSuchBucketPolicy", "The bucket policy does not exist"))
			continue
		}
		r, body := s.recorded(setting.op, func(r collectortest.Response) bool {
			return !strings.Contains(r.Body, `"Status":`) && !strings.Contains(r.Body, `"LoggingEnabled":`)
		})
		r.URL = url
		s.add(r, body)
	}
}

// s3Error answers an S3 call with S3's 404 for code, in the recorded 404s'
// shape.
func (s *awsSim) s3Error(op, url, bucket, code, message string) (collectortest.Response, map[string]any) {
	r, body := s.recorded("aws.s3.GetPublicAccessBlock", func(r collectortest.Response) bool { return r.Status == http.StatusNotFound })
	r.Operation, r.URL = op, url
	e := simFirst(body, "Error")
	e["Code"], e["Message"], e["BucketName"] = code, message, bucket
	e["RequestId"] = simulate.Base62("", 16, "s3-request", url)
	return r, body
}

// securityGroups answers each region's security groups. A rule's protocol
// is EC2's, such as tcp or -1 for all traffic, and its sources are CIDR
// blocks, IPv6 ones in ipv6Ranges. EC2 has one port range a rule, so a
// roster rule with several ports is one rule for each, and * is every
// port. A group's name is the part of its key after the region, or its
// name extra.
func (s *awsSim) securityGroups() {
	for _, region := range s.regions() {
		r, body := s.recorded("aws.ec2.DescribeSecurityGroups", func(r collectortest.Response) bool {
			return strings.Contains(r.URL, "ec2."+region+".")
		})
		groups := simItems(body, "DescribeSecurityGroupsResponse", "securityGroupInfo", "item")
		var items []any
		for _, g := range s.r.SecurityGroups {
			if s.regionOf(g.Extra) != region {
				continue
			}
			name := g.Key[strings.LastIndex(g.Key, "/")+1:]
			simulate.Extra(g.Extra, "name", &name)
			item, recorded := simPick(groups, "groupName", name)
			if !recorded {
				id := "sg-" + strings.ToLower(simulate.Base62("", 17, "sg", g.Key))
				item["groupId"], item["groupName"], item["groupDescription"] = id, name, name
				item["securityGroupArn"] = "arn:aws:ec2:" + region + ":" + s.account.ID + ":security-group/" + id
			}
			var inbound, outbound []any
			for _, rule := range g.Rules {
				if rule.Access != roster.Allow {
					panic("simulator: EC2 security groups have no deny rules, and " + g.Key + "/" + rule.Key + " denies")
				}
				for _, p := range simPermissions(rule) {
					if rule.Direction == roster.Inbound {
						inbound = append(inbound, p)
					} else {
						outbound = append(outbound, p)
					}
				}
			}
			item["ipPermissions"], item["ipPermissionsEgress"] = simList("item", inbound), simList("item", outbound)
			items = append(items, item)
		}
		simFirst(body, "DescribeSecurityGroupsResponse")["securityGroupInfo"] = simList("item", items)
		s.add(r, body)
	}
}

func simPermissions(rule roster.NetworkRule) []any {
	var v4, v6 []any
	for _, src := range rule.Sources {
		if strings.Contains(src, ":") {
			v6 = append(v6, map[string]any{"cidrIpv6": src})
		} else {
			v4 = append(v4, map[string]any{"cidrIp": src})
		}
	}
	ranges := map[string]any{"groups": "", "ipRanges": simList("item", v4), "ipv6Ranges": simList("item", v6), "prefixListIds": ""}
	if rule.Protocol == "-1" {
		p := simCopy(ranges)
		p["ipProtocol"] = "-1"
		return []any{p}
	}
	var out []any
	for _, port := range rule.Ports {
		from, to := port, port
		if port == "*" {
			from, to = "0", "65535"
		} else if lo, hi, ok := strings.Cut(port, "-"); ok {
			from, to = lo, hi
		}
		p := simCopy(ranges)
		p["ipProtocol"], p["fromPort"], p["toPort"] = rule.Protocol, from, to
		out = append(out, p)
	}
	return out
}

// cloudTrail answers each region's trails and each trail's status. An
// audit log is a trail. One whose regions hold * is a multi-region trail in
// its home_region extra, or the first region scanned, which every region
// lists, and another is a trail in its one region. A trail logs while the
// audit log is enabled, and records global service events unless its
// global_service_events extra is false. It records every management event
// with no event selectors of its own, unless its event_selectors extra
// names some, which the collector reads with GetEventSelectors and the
// recording answers. Each trail delivers to the recorded trails' bucket.
func (s *awsSim) cloudTrail() {
	type trail struct {
		name, home      string
		multi, logging  bool
		selectors       string
		globalEventsOff bool
	}
	var trails []trail
	for _, l := range s.account.AuditLogs {
		t := trail{name: l.Key, home: s.home(), multi: slices.Contains(l.Regions, "*"), logging: l.Enabled}
		simulate.Extra(l.Extra, "home_region", &t.home)
		simulate.Extra(l.Extra, "event_selectors", &t.selectors)
		global := true
		simulate.Extra(l.Extra, "global_service_events", &global)
		t.globalEventsOff = !global
		if !t.multi {
			if len(l.Regions) != 1 {
				panic("simulator: a CloudTrail trail logs one region or every region, and " + l.Key + " lists " + strings.Join(l.Regions, ", "))
			}
			t.home = l.Regions[0]
		}
		trails = append(trails, t)
	}
	arn := func(t trail) string {
		return "arn:aws:cloudtrail:" + t.home + ":" + s.account.ID + ":trail/" + t.name
	}
	for _, region := range s.regions() {
		r, body := s.recorded("aws.cloudtrail.DescribeTrails", func(r collectortest.Response) bool {
			return strings.Contains(r.URL, "cloudtrail."+region+".")
		})
		recorded := simItems(body, "trailList")
		var items []any
		for _, t := range trails {
			if t.home != region && !t.multi {
				continue
			}
			item, _ := simPick(recorded, "Name", t.name)
			item["Name"], item["TrailARN"], item["HomeRegion"] = t.name, arn(t), t.home
			item["IsMultiRegionTrail"], item["HasCustomEventSelectors"], item["IncludeGlobalServiceEvents"] = t.multi, t.selectors != "", !t.globalEventsOff
			items = append(items, item)
		}
		body["trailList"] = simNonNil(items)
		s.add(r, body)

		for _, t := range trails {
			logging := `"IsLogging":` + strconv.FormatBool(t.logging)
			r, body := s.recorded("aws.cloudtrail.GetTrailStatus", func(r collectortest.Response) bool {
				return strings.Contains(r.RequestBody, arn(t)) && strings.Contains(r.Body, logging)
			}, func(r collectortest.Response) bool { return strings.Contains(r.Body, logging) })
			r.URL = "https://cloudtrail." + region + ".amazonaws.com/?"
			r.RequestBody = simJSON(map[string]any{"Name": arn(t)})
			s.add(r, body)
		}
	}
}

// rds answers each region's DB instances, one for each of the roster's
// databases there. A database runs MySQL unless its engine extra says
// otherwise, keeps automated backups for its backup retention, or has them
// off, and runs in several availability zones as a Multi-AZ instance. It
// is encrypted unless its key source maps to none, and publicly
// accessible unless its network access maps to off. It names no security
// group, so the collector reads none for its port.
func (s *awsSim) rds() {
	for _, region := range s.regions() {
		r, body := s.recorded("aws.rds.DescribeDBInstances", func(r collectortest.Response) bool {
			return strings.Contains(r.URL, "rds."+region+".")
		})
		var items []any
		for _, d := range s.r.Cloud.Databases {
			if s.regionOf(d.Extra) != region {
				continue
			}
			engine := "mysql"
			simulate.Extra(d.Extra, "engine", &engine)
			retention := 0
			if d.BackupRetentionDays != nil {
				retention = *d.BackupRetentionDays
			}
			encrypted := s.keySource(d.KeySource) != roster.NoKey
			db := map[string]any{
				"DBInstanceIdentifier": d.Key, "DBInstanceClass": "db.t4g.micro", "Engine": engine, "EngineVersion": "8.0.39",
				"DBInstanceStatus": "available", "MasterUsername": "admin", "AllocatedStorage": "20", "StorageType": "gp3",
				"InstanceCreateTime": s.days(100), "PreferredBackupWindow": "03:00-04:00", "BackupRetentionPeriod": strconv.Itoa(retention),
				"MultiAZ": strconv.FormatBool(d.Zones > 1), "AutoMinorVersionUpgrade": "true", "DeletionProtection": "false",
				"PubliclyAccessible": strconv.FormatBool(s.r.Terms.CloudNetworkAccess[d.NetworkAccess] != roster.NetworkOff),
				"StorageEncrypted":   strconv.FormatBool(encrypted), "VpcSecurityGroups": "",
				"DBInstanceArn": "arn:aws:rds:" + region + ":" + s.account.ID + ":db:" + d.Key,
				"DbiResourceId": "db-" + simulate.Base62("", 26, "dbi", d.Key),
				"Endpoint": map[string]any{
					"Address": d.Key + ".c0example." + region + ".rds.amazonaws.com", "Port": "3306", "HostedZoneId": "Z2R2ITUGPM61AM",
				},
			}
			switch s.keySource(d.KeySource) {
			case roster.CustomerKey:
				db["KmsKeyId"] = s.keyARN(region, d.Key)
			case roster.ProviderKey:
				db["KmsKeyId"] = "arn:aws:kms:" + region + ":" + s.account.ID + ":key/" + simulate.UUID("kms", "aws/rds")
			}
			items = append(items, db)
		}
		simFirst(body, "DescribeDBInstancesResponse", "DescribeDBInstancesResult")["DBInstances"] = simList("DBInstance", items)
		s.add(r, body)
	}
}

// kms answers each region's KMS keys: the recording's AWS managed keys,
// and a customer managed key for each bucket and database whose key source
// maps to customer_key, with rotation on.
func (s *awsSim) kms() {
	customer := map[string][]string{}
	for _, st := range s.r.Storage {
		if s.keySource(st.KeySource) == roster.CustomerKey {
			region := s.regionOf(st.Extra)
			customer[region] = append(customer[region], s.keyARN(region, st.Key))
		}
	}
	for _, d := range s.r.Cloud.Databases {
		if s.keySource(d.KeySource) == roster.CustomerKey {
			region := s.regionOf(d.Extra)
			customer[region] = append(customer[region], s.keyARN(region, d.Key))
		}
	}
	for _, region := range s.regions() {
		host := "kms." + region + "."
		inRegion := func(r collectortest.Response) bool { return strings.Contains(r.URL, host) }
		r, body := s.recorded("aws.kms.ListKeys", inRegion)
		keys, _ := body["Keys"].([]any)
		for _, arn := range customer[region] {
			keys = append(keys, map[string]any{"KeyArn": arn, "KeyId": arn[strings.LastIndex(arn, "/")+1:]})
		}
		body["Keys"], body["KeyCount"] = simNonNil(keys), len(keys)
		s.add(r, body)

		for _, resp := range s.rec.responses {
			if resp.Operation == "aws.kms.DescribeKey" && inRegion(resp) {
				s.out = append(s.out, s.rewrite(resp))
			}
		}
		for _, arn := range customer[region] {
			id := arn[strings.LastIndex(arn, "/")+1:]
			r, body := s.recorded("aws.kms.DescribeKey", inRegion)
			r.RequestBody = simJSON(map[string]any{"KeyId": id})
			meta := body["KeyMetadata"].(map[string]any)
			meta["KeyId"], meta["Arn"], meta["KeyManager"], meta["Description"] = id, arn, "CUSTOMER", "Simulated customer managed key"
			s.add(r, body)

			rot := collectortest.Response{
				Operation: "aws.kms.GetKeyRotationStatus", Method: http.MethodPost, URL: r.URL, Header: r.Header.Clone(),
				RequestBody: simJSON(map[string]any{"KeyId": id}),
			}
			s.add(rot, map[string]any{"KeyId": arn, "KeyRotationEnabled": true, "RotationPeriodInDays": 365, "NextRotationDate": s.now.AddDate(0, 6, 0).Unix()})
		}
	}
}
