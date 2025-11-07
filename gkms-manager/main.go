package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gkms "gkms/common"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
)

func getServiceAccountID(vmid string) string {
	return fmt.Sprintf("vm-%s", vmid)
}

func generateRandomKey(size int) (string, error) {
	keyBytes := make([]byte, size)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(keyBytes), nil
}

func createServiceAccount(ctx context.Context, iamService *iam.Service, vmid string) (*iam.ServiceAccount, error) {
	accountID := getServiceAccountID(vmid)
	saName := fmt.Sprintf("projects/%s/serviceAccounts/%s@%s.iam.gserviceaccount.com", gkms.ProjectID, accountID, gkms.ProjectID)

	sa, err := iamService.Projects.ServiceAccounts.Get(saName).Context(ctx).Do()
	if err == nil {
		log.Printf("Service account %s already exists", sa.Email)
		return sa, nil
	}

	req := &iam.CreateServiceAccountRequest{
		AccountId: accountID,
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: fmt.Sprintf("VM Service Account for %s", vmid),
			Description: "Used by a specific VM to access its own secrets.",
		},
	}
	sa, err = iamService.Projects.ServiceAccounts.Create(fmt.Sprintf("projects/%s", gkms.ProjectID), req).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to create service account: %w", err)
	}
	log.Printf("Created Service Account: %s", sa.Email)
	return sa, nil
}

func createAndStoreSecret(ctx context.Context, smClient *secretmanager.Client, vmid, secretName, payload string, newPassphrase bool) (string, error) {
	secretID := gkms.GetSecretID(vmid, secretName)
	if secretID == "" {
		return "", fmt.Errorf("unknown secret short name: %s", secretName)
	}
	parent := fmt.Sprintf("projects/%s", gkms.ProjectID)

	createReq := &secretmanagerpb.CreateSecretRequest{
		Parent:   parent,
		SecretId: secretID,
		Secret: &secretmanagerpb.Secret{
			Labels: map[string]string{
				"vm-id": vmid,
			},
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	}
	secret, err := smClient.CreateSecret(ctx, createReq)
	if err != nil && !isAlreadyExists(err) {
		return "", fmt.Errorf("failed to create secret %s: %w", secretID, err)
	}
	if secret == nil { // It already existed
		secret, err = smClient.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
			Name: fmt.Sprintf("%s/secrets/%s", parent, secretID),
		})
		if err != nil {
			return "", fmt.Errorf("failed to get existing secret %s: %w", secretID, err)
		}
		// Do not regenerate secretPasshprase
		if secretName == gkms.SecretPassphraseName && !newPassphrase {
			return secret.Name, nil
		}
	}
	log.Printf("Ensured secret exists: %s", secret.Name)

	addVerReq := &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: []byte(payload),
		},
	}
	if _, err := smClient.AddSecretVersion(ctx, addVerReq); err != nil {
		return "", fmt.Errorf("failed to add secret version: %w", err)
	}

	return secret.Name, nil
}

func grantSecretAccess(ctx context.Context, smClient *secretmanager.Client, secretFullName, saEmail string) error {
	policy, err := smClient.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{
		Resource: secretFullName,
	})
	if err != nil {
		return fmt.Errorf("failed to get IAM policy for secret: %w", err)
	}

	saMember := "serviceAccount:" + saEmail
	role := "roles/secretmanager.secretAccessor"

	for _, binding := range policy.Bindings {
		if binding.Role == role {
			for _, member := range binding.Members {
				if member == saMember {
					log.Printf("SA %s already has access to %s.", saEmail, secretFullName)
					return nil
				}
			}
		}
	}

	policy.Bindings = append(policy.Bindings, &iampb.Binding{
		Role:    role,
		Members: []string{saMember},
	})

	setPolicyReq := &iampb.SetIamPolicyRequest{
		Resource: secretFullName,
		Policy:   policy,
	}
	if _, err := smClient.SetIamPolicy(ctx, setPolicyReq); err != nil {
		return fmt.Errorf("failed to set IAM policy for secret: %w", err)
	}

	log.Printf("Granted SA %s access to %s.", saEmail, secretFullName)
	return nil
}

func createAndSaveKeyFile(ctx context.Context, iamService *iam.Service, saEmail, vmid string) error {
	saName := fmt.Sprintf("projects/-/serviceAccounts/%s", saEmail)
	keyReq := &iam.CreateServiceAccountKeyRequest{}

	key, err := iamService.Projects.ServiceAccounts.Keys.Create(saName, keyReq).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to create service account key: %w", err)
	}

	keyData, err := base64.StdEncoding.DecodeString(key.PrivateKeyData)
	if err != nil {
		return fmt.Errorf("failed to decode key data: %w", err)
	}

	keyFileName := fmt.Sprintf("%s-key.json", vmid)
	err = os.WriteFile(keyFileName, keyData, gkms.KeyFilePermission)
	if err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	log.Printf("✅ Success! VM key file created: %s", keyFileName)
	log.Printf("   This file should be securely copied to the VM.")
	return nil
}

func deleteServiceAccount(ctx context.Context, iamService *iam.Service, vmid string) error {
	accountID := getServiceAccountID(vmid)
	saName := fmt.Sprintf("projects/%s/serviceAccounts/%s@%s.iam.gserviceaccount.com", gkms.ProjectID, accountID, gkms.ProjectID)

	_, err := iamService.Projects.ServiceAccounts.Delete(saName).Context(ctx).Do()
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("failed to delete service account: %w", err)
	}
	if isNotFound(err) {
		log.Printf("Service Account %s already deleted.", accountID)
	} else {
		log.Printf("Deleted Service Account: %s", accountID)
	}
	return nil
}

func deleteSecret(ctx context.Context, smClient *secretmanager.Client, vmid, secretName string) error {
	secretID := gkms.GetSecretID(vmid, secretName)
	if secretID == "" {
		return fmt.Errorf("unknown secret short name: %s", secretName)
	}
	name := fmt.Sprintf("projects/%s/secrets/%s", gkms.ProjectID, secretID)

	delReq := &secretmanagerpb.DeleteSecretRequest{Name: name}
	err := smClient.DeleteSecret(ctx, delReq)
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("failed to delete secret %s: %w", secretID, err)
	}
	if isNotFound(err) {
		log.Printf("Secret %s already deleted.", secretID)
	} else {
		log.Printf("Deleted Secret: %s", secretID)
	}
	return nil
}

func createVM(ctx context.Context, smClient *secretmanager.Client, iamService *iam.Service, newPassphrase bool, vmid, env, dockerCreds string) error {
	sa, err := createServiceAccount(ctx, iamService, vmid)
	if err != nil {
		return err
	}
	// Small delay to allow SA to propagate before setting IAM
	time.Sleep(2 * time.Second)

	passphrase, err := generateRandomKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate passphrase: %w", err)
	}
	passSecretName, err := createAndStoreSecret(ctx, smClient, vmid, gkms.SecretPassphraseName, passphrase, newPassphrase)
	if err != nil {
		return err
	}
	if err := grantSecretAccess(ctx, smClient, passSecretName, sa.Email); err != nil {
		return err
	}
	log.Printf("Stored and granted access to %s", gkms.SecretPassphraseName)

	if env != "" {
		envSecretName, err := createAndStoreSecret(ctx, smClient, vmid, gkms.SecretEnvName, env, false)
		if err != nil {
			return err
		}
		if err := grantSecretAccess(ctx, smClient, envSecretName, sa.Email); err != nil {
			return err
		}
		log.Printf("Stored and granted access to %s", gkms.SecretEnvName)
	} else {
		log.Printf("Skipping %s (optional): no value provided.", gkms.SecretEnvName)
	}

	if dockerCreds != "" {
		dockerSecretName, err := createAndStoreSecret(ctx, smClient, vmid, gkms.SecretDockerName, dockerCreds, false)
		if err != nil {
			return err
		}
		if err := grantSecretAccess(ctx, smClient, dockerSecretName, sa.Email); err != nil {
			return err
		}
		log.Printf("Stored and granted access to %s", gkms.SecretDockerName)
	} else {
		log.Printf("Skipping %s (optional): no value provided.", gkms.SecretDockerName)
	}

	if err := createAndSaveKeyFile(ctx, iamService, sa.Email, vmid); err != nil {
		return err
	}

	return nil
}

func deleteVM(ctx context.Context, smClient *secretmanager.Client, iamService *iam.Service, vmid string) error {
	if err := deleteSecret(ctx, smClient, vmid, gkms.SecretPassphraseName); err != nil {
		log.Printf("Warning: failed to delete passphrase secret: %v", err)
	}
	if err := deleteSecret(ctx, smClient, vmid, gkms.SecretEnvName); err != nil {
		log.Printf("Warning: failed to delete env secret: %v", err)
	}
	if err := deleteSecret(ctx, smClient, vmid, gkms.SecretDockerName); err != nil {
		log.Printf("Warning: failed to delete docker secret: %v", err)
	}

	if err := deleteServiceAccount(ctx, iamService, vmid); err != nil {
		return fmt.Errorf("failed to delete service account: %w", err)
	}

	log.Printf("✅ Cleanup complete for %s.", vmid)
	return nil
}

func main() {
	op := flag.String("op", "", "Operation: 'create' or 'delete'")
	keyFile := flag.String("key", "", "Path to the manager's admin service account key file")
	vmUID := flag.String("vm-uid", "", "Unique ID for the VM")
	env := flag.String("env", "", "Environment string payload (for 'create' op)")
	newPassphrase := flag.Bool("new-passphrase", false, "Regenerate passhprase")
	dockerCreds := flag.String("docker", "", "Docker credentials payload (for 'create' op)")

	flag.Parse()

	if *op == "" || *keyFile == "" || *vmUID == "" {
		log.Fatal("Error: -op, -key and -vm-uid are required flags.")
	}

	ctx := context.Background()
	creds := option.WithCredentialsFile(*keyFile)
	smClient, err := secretmanager.NewClient(ctx, creds)
	if err != nil {
		log.Fatalf("Failed to create Secret Manager client: %v", err)
	}
	defer smClient.Close()

	iamService, err := iam.NewService(ctx, creds)
	if err != nil {
		log.Fatalf("Failed to create IAM service: %v", err)
	}

	switch *op {
	case "create":
		err := createVM(ctx, smClient, iamService, *newPassphrase, *vmUID, *env, *dockerCreds)
		if err != nil {
			log.Fatalf("Failed to create VM resources: %v", err)
		}

	case "delete":
		err := deleteVM(ctx, smClient, iamService, *vmUID)
		if err != nil {
			log.Fatalf("Failed to delete VM resources: %v", err)
		}

	default:
		log.Fatalf("Unknown operation: %s. Use 'create' or 'delete'.", *op)
	}
}

// --- gRPC Error Helpers ---
func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "rpc error: code = AlreadyExists desc = Secret")
}

func isNotFound(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "rpc error: code = NotFound desc = Secret") || strings.Contains(err.Error(), "rpc error: code = NotFound desc = Service account"))
}
