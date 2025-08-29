// TODO: FIXME: prepend license
// Copyright (c) 2025 privateLINE, LLC.

package types

type FirewallError struct {
	ContainedErr error

	OtherVpnUnknownToUs bool
	OtherVpnName        string
	OtherVpnGUID        string
}

func (fe *FirewallError) Error() string {
	return fe.ContainedErr.Error()
}

func (fe *FirewallError) GetContainedErr() error {
	return fe.ContainedErr
}

func (fe *FirewallError) GetOtherVpnName() string {
	return fe.OtherVpnName
}

func (fe *FirewallError) GetOtherVpnGUID() string {
	return fe.OtherVpnGUID
}

func (fe *FirewallError) GetOtherVpnUnknownToUs() bool {
	return fe.OtherVpnUnknownToUs
}
