@echo off
echo This tests connectivity with expected minimum path MTU of 1280 over IPv4

echo ----------------------------------------------------
echo Testing connectivity to Wireguard gateway
ping -4 -f -l 1280 155.130.218.74

echo ----------------------------------------------------
echo Testing connectivity to api.privateline.io
ping -4 -f -l 1280 api.privateline.io
