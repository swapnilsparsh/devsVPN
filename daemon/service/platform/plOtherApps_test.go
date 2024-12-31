package platform

import (
	"fmt"
	"testing"
)

func TestPlApps(t *testing.T) {
	plOtherPaths, err := PLOtherAppsToAcceptIncomingConnections()
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("%d entries\n", len(plOtherPaths))
		for _, entry := range plOtherPaths {
			fmt.Println(entry)
		}
	}
}
