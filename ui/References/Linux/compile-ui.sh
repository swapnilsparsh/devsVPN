#!/bin/bash

# Building electron app (result can be found here: dist/privateline-connect-ui-XXX.AppImage)
# Configuring app version in file 'package.json'

cd "$(dirname "$0")"
cd ../..

echo "[+] Building..."
npm run electron:build
