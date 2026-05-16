//  Daemon for privateLINE Connect Desktop
//  https://github.com/swapnilsparsh/devsVPN
//
//  Copyright (c) 2025 privateLINE, LLC.
//
//  This file is part of the Daemon for privateLINE Connect Desktop.
//
//  The Daemon for privateLINE Connect Desktop is free software: you can redistribute it and/or
//  modify it under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option) any later version.
//
//  The Daemon for privateLINE Connect Desktop is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
//  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
//  details.
//
//  You should have received a copy of the GNU General Public License
//  along with the Daemon for privateLINE Connect Desktop. If not, see <https://www.gnu.org/licenses/>.

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
