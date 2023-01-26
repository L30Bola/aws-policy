package awspolicy

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

var validatePolicies = []struct {
	inputPolicy  []byte
	outputPolicy Policy
	parsed       error
}{
	{
		inputPolicy: []byte(`
	{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": [
					"sts:AssumeRole"
				],
				"Principal": {
					"AWS": "arn:aws:iam::1234567890:root"
				},
				"Resource": [
					"arn:aws:iam::99999999999:role/admin"
				],
				"Condition": {
				    "StringEqualsIgnoreCase": {
						"aws:PrincipalTag/department": [ "finance", "hr", "legal" ],
						"aws:PrincipalTag/role": [ "audit", "security" ]
				  	},
				  	"StringEquals": {
						"aws:PrincipalAccount": "99999999999"
				  	}
				}
			}
		] 
	}
	`), outputPolicy: Policy{
			Version: "2012-10-17",
			ID:      "",
			Statements: []Statement{
				{
					Effect: "Allow",
					Action: []string{
						"sts:AssumeRole",
					},
					Principal: map[string][]string{
						"AWS": {"arn:aws:iam::1234567890:root"},
					},
					Resource: []string{
						"arn:aws:iam::99999999999:role/admin",
					},
					Condition: Condition{
						"StringEqualsIgnoreCase": {
							"aws:PrincipalTag/department": []string{
								"finance",
								"hr",
								"legal",
							},
							"aws:PrincipalTag/role": []string{
								"audit",
								"security",
							},
						},
						"StringEquals": {
							"aws:PrincipalAccount": []string{
								"99999999999",
							},
						},
					},
				},
			},
		}, parsed: nil,
	},
	{
		inputPolicy: []byte(`
			{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": [
							"athena:*"
						],
						"Resource": [
							"arn:aws:athena:eu-west-5:*:workgroup/AthenaWorkGroup"
						]
					},
					{
						"Effect": "Allow",
						"Action": [
							"glue:GetDatabase",
							"glue:GetDatabases",
							"glue:CreateTable",
							"glue:UpdateTable",
							"glue:GetTable",
							"glue:GetTables",
							"glue:GetPartition",
							"glue:GetPartitions",
							"glue:BatchGetPartition",
							"glue:GetCatalogImportStatus"
						],
						"Resource": [
							"*"
						]
					},
					{
						"Effect": "Allow",
						"Action": [
							"s3:GetObject",
							"s3:ListBucket",
							"s3:ListBucketMultipartUploads",
							"s3:ListMultipartUploadParts",
							"s3:AbortMultipartUpload",
							"s3:CreateBucket",
							"s3:ListAllMyBuckets",
							"s3:GetBucketLocation"
						],
						"Resource": [
							"arn:aws:s3:::bucket1",
							"arn:aws:s3:::bucket1/*"
						]
					}
				]
			}		
			`),
		outputPolicy: Policy{
			Version: "2012-10-17",
			Statements: []Statement{
				{
					Effect: "Allow",
					Action: []string{"athena:*"},
					Resource: []string{
						"arn:aws:athena:eu-west-5:*:workgroup/AthenaWorkGroup",
					},
				},
				{
					Effect: "Allow",
					Action: []string{
						"glue:GetDatabase",
						"glue:GetDatabases",
						"glue:CreateTable",
						"glue:UpdateTable",
						"glue:GetTable",
						"glue:GetTables",
						"glue:GetPartition",
						"glue:GetPartitions",
						"glue:BatchGetPartition",
						"glue:GetCatalogImportStatus",
					},
					Resource: []string{
						"*",
					},
				},
				{
					Effect: "Allow",
					Action: []string{
						"s3:GetObject",
						"s3:ListBucket",
						"s3:ListBucketMultipartUploads",
						"s3:ListMultipartUploadParts",
						"s3:AbortMultipartUpload",
						"s3:CreateBucket",
						"s3:ListAllMyBuckets",
						"s3:GetBucketLocation",
					},
					Resource: []string{
						"arn:aws:s3:::bucket1",
						"arn:aws:s3:::bucket1/*",
					},
				},
			},
		},
		parsed: nil,
	},
}

func TestParsePolicies(t *testing.T) {
	for _, test := range validatePolicies {
		var policy Policy
		t.Run(string(test.inputPolicy), func(t *testing.T) {
			got := policy.UnmarshalJSON(test.inputPolicy)
			if got != test.parsed {
				t.Errorf("Expected: %+v, got: %+v", test.parsed, got)
			}
			if !cmp.Equal(test.outputPolicy, policy) {
				t.Errorf("Expected: %+v, got: %+v", test.outputPolicy, policy)
			}
		})
	}
}
