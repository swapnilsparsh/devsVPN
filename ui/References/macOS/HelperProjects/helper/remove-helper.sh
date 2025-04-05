#!/bin/sh
sudo launchctl unload /Library/LaunchDaemons/net.privateline-connect.client.Helper.plist
sudo rm /Library/LaunchDaemons/net.privateline-connect.client.Helper.plist
sudo rm /Library/PrivilegedHelperTools/net.privateline-connect.client.Helper
