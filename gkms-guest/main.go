package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gkms "gkms/common"
	"google.golang.org/api/option"
)

func getSecret(ctx context.Context, smClient *secretmanager.Client, vmUID, secretName string) (string, error) {
	secretID := gkms.GetSecretID(vmUID, secretName)
	if secretID == "" {
		return "", fmt.Errorf("unknown secret short name: %s", secretName)
	}

	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", gkms.ProjectID, secretID)

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}
	result, err := smClient.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access secret %s: %w", secretName, err)
	}

	return string(result.Payload.Data), nil
}

func main() {
	keyFile := flag.String("key", "", "Path to this VM's unique service account key file")
	vmUID := flag.String("vm-uid", "", "The unique ID for this VM")
	secretName := flag.String("secret", "", "Name of the secret to get (e.g., 'SECRET_VM_ENV')")

	flag.Parse()

	if *vmUID == "" || *secretName == "" {
		log.Fatal("Error: -key, -vm-uid and -secret are required flags.")
	}

	ctx := context.Background()

	creds := option.WithCredentialsFile(*keyFile)
	smClient, err := secretmanager.NewClient(ctx, creds)
	if err != nil {
		log.Fatalf("Failed to create Secret Manager client: %v", err)
	}
	defer smClient.Close()

	payload, err := getSecret(ctx, smClient, *vmUID, *secretName)
	if err != nil {
		log.Fatalf("Failed to get secret: %v", err)
	}

	fmt.Print(payload)
}
