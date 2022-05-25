#!/usr/bin/env sh

url=https://github.com/ethereum/staking-deposit-cli/releases/download/v2.2.0/staking_deposit-cli-9ab0b05-linux-amd64.tar.gz
wget $url
tar -zxf staking_deposit-cli-*-linux-amd64.tar.gz
cp staking_deposit-cli-*-linux-amd64/deposit .
rm -rf staking_deposit-cli-*-linux-amd64*
