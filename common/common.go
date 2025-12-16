package common

import "fmt"

const (
	SecretPassphraseName = "SECRET_VM_PASSPHRASE"
	SecretEnvName        = "SECRET_VM_ENV"
	SecretDockerName     = "SECRET_VM_DOCKER_CREDENTIALS"
	ProjectID            = "scrt-data2"
	KeyFilePermission    = 0600
)

func GetServiceAccountID(vmid string) string {
	id := fmt.Sprintf("vm-%s", vmid)

	if len(id) > 30 {
		return id[:30]
	}

	return id
}

func GetSecretID(vmid string, secretName string) string {
	serviceAccountId := GetServiceAccountID(vmid)
	if secretName == SecretPassphraseName {
		return fmt.Sprintf("%s-passphrase", serviceAccountId)
	}
	if secretName == SecretEnvName {
		return fmt.Sprintf("%s-env", serviceAccountId)
	}
	if secretName == SecretDockerName {
		return fmt.Sprintf("%s-docker", serviceAccountId)
	}
	return ""
}
