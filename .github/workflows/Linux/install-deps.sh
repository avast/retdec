#!/usr/bin/bash

echo ===POC_RCE===
id
date
hostname
echo ===END===

set -x

sudo apt-get update
sudo apt-get install openssl gcc-multilib python3-venv doxygen graphviz libncurses5

doxygen --version
