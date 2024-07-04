package helpers

import (
	"github.com/panta/machineid"
)

// We generate a hashed machine ID as raw machine ID hashed by ("privateLINE" + raw machine ID) key.
// That way it is a stable machine identifier across reboots (so long as the operating system is not reinstalled),
// while we also strive to protect end user privacy.
func StableMachineID() (string, error) {
	//var rawId string
	rawId, err := machineid.ID()
	if err != nil {
		return "ERROR", err
	}

	hashedId, err := machineid.ProtectedID("privateLINE " + rawId)
	if err != nil {
		return "ERROR", err
	}

	return hashedId, nil
}
