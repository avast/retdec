#!/usr/bin/bash

set -x

sudo apt-get update
sudo apt-get install openssl gcc-multilib python3-venv doxygen graphviz libncurses5

doxygen --version
