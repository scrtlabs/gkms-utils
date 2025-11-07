package common

import "fmt"

const (
	SecretPassphraseName = "SECRET_VM_PASSPHRASE"
	SecretEnvName        = "SECRET_VM_ENV"
	SecretDockerName     = "SECRET_VM_DOCKER_CREDENTIALS"
	ProjectID            = "scrt-data2"
	KeyFilePermission    = 0600
)

func GetSecretID(vmid string, secretName string) string {
	if secretName == SecretPassphraseName {
		return fmt.Sprintf("vm-%s-passphrase", vmid)
	}
	if secretName == SecretEnvName {
		return fmt.Sprintf("vm-%s-env", vmid)
	}
	if secretName == SecretDockerName {
		return fmt.Sprintf("vm-%s-docker", vmid)
	}
	return ""
}
