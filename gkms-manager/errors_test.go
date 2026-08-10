package main

import (
	"fmt"
	"testing"

	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrorHelpers(t *testing.T) {
	// Shapes the two clients actually produce.
	iamNotFound := &googleapi.Error{
		Code:    404,
		Message: "Service account projects/-/serviceAccounts/vm-abc@p.iam.gserviceaccount.com does not exist.",
	}
	smNotFound := status.Error(codes.NotFound, "Secret [projects/1/secrets/vm-abc-passphrase] not found.")
	smAlreadyExists := status.Error(codes.AlreadyExists, "Secret [projects/1/secrets/vm-abc-passphrase] already exists.")
	smPropagation := status.Error(codes.InvalidArgument, "Service account vm-abc@p.iam.gserviceaccount.com does not exist.")
	permDenied := status.Error(codes.PermissionDenied, "denied")

	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"iam 404 is NotFound (was the bug)", isNotFound(iamNotFound), true},
		{"iam 404 wrapped is NotFound", isNotFound(fmt.Errorf("wrap: %w", iamNotFound)), true},
		{"sm NotFound", isNotFound(smNotFound), true},
		{"sm AlreadyExists is not NotFound", isNotFound(smAlreadyExists), false},
		{"nil is not NotFound", isNotFound(nil), false},
		{"permission denied is not NotFound", isNotFound(permDenied), false},

		{"sm AlreadyExists", isAlreadyExists(smAlreadyExists), true},
		{"sm NotFound is not AlreadyExists", isAlreadyExists(smNotFound), false},
		{"nil is not AlreadyExists", isAlreadyExists(nil), false},

		{"sm InvalidArgument SA is propagation", isSAPropagationError(smPropagation), true},
		{"iam 404 SA is propagation", isSAPropagationError(iamNotFound), true},
		{"wrapped propagation still matches", isSAPropagationError(fmt.Errorf("failed to set IAM policy for secret: %w", smPropagation)), true},
		{"secret-not-found is not propagation", isSAPropagationError(smNotFound), false},
		{"permission denied is not propagation", isSAPropagationError(permDenied), false},
		{"nil is not propagation", isSAPropagationError(nil), false},
	}

	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}
