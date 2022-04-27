module github.com/hashicorp/vault-tools/vault-recovery-key

go 1.18

require (
	github.com/golang/protobuf v1.5.2
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-kms-wrapping v0.7.0
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.5
	github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2 v2.0.0
	github.com/hashicorp/go-kms-wrapping/wrappers/azurekeyvault/v2 v2.0.0
	github.com/hashicorp/go-kms-wrapping/wrappers/gcpckms/v2 v2.0.0
	github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2 v2.0.0
	github.com/hashicorp/vault v1.10.1
	github.com/sirupsen/logrus v1.8.1
	github.com/tencentcloud/tencentcloud-sdk-go v3.0.171+incompatible // indirect
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f
	google.golang.org/protobuf v1.28.0 // indirect
)
