// TODO FIXME: prepend license
// Copyright (c) 2025 privateLINE, LLC.

package types

type FirewallError struct {
	containedErr error

	otherVpnUnknownToUs bool
	otherVpnName        string
	otherVpnGUID        string
}

func (fe *FirewallError) Error() string {
	return fe.containedErr.Error()
}

func (fe *FirewallError) GetContainedErr() error {
	return fe.containedErr
}

func (fe *FirewallError) OtherVpnName() string {
	return fe.otherVpnName
}

func (fe *FirewallError) OtherVpnGUID() string {
	return fe.otherVpnGUID
}

func (fe *FirewallError) OtherVpnUnknownToUs() bool {
	return fe.otherVpnUnknownToUs
}
