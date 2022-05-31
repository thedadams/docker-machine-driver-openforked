package openforked

import (
	"testing"

	"github.com/rancher/machine/libmachine/drivers"
)

func TestSetConfigFromFlags(t *testing.T) {
	driver := NewDriver("default", "path")

	checkFlags := &drivers.CheckDriverOptions{
		FlagsValues: map[string]interface{}{
			"openforked-auth-url":  "http://url",
			"openforked-username":  "user",
			"openforked-password":  "pwd",
			"openforked-tenant-id": "ID",
			"openforked-flavor-id": "ID",
			"openforked-image-id":  "ID",
		},
		CreateFlags: driver.GetCreateFlags(),
	}

	if err := driver.SetConfigFromFlags(checkFlags); err != nil {
		t.Fatal(err)
	}

	if len(checkFlags.InvalidFlags) != 0 {
		t.Fatalf("invalid flags %v", checkFlags.InvalidFlags)
	}
}
