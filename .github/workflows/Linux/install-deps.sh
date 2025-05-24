#!/usr/bin/bash

set -x

sudo apt-get update
sudo apt-get install openssl gcc-multilib python3-venv doxygen graphviz libncurses6

doxygen --version
