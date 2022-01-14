#!/usr/bin/bash

RD=$PWD

# Get current branch of RetDec
# > GITHUB_BASE_REF is set on PR, empty otherwise.
RD_BRANCH=${GITHUB_HEAD_REF:-${GITHUB_REF_NAME}}

echo "RetDec branch: $RD_BRANCH"

# Clone regression tests.
git clone https://github.com/avast/retdec-regression-tests
cd retdec-regression-tests

# Checkout the same branch if possible.
git checkout "$RD_BRANCH" || git checkout master

echo "RetDec RT branch: $(git rev-parse --abbrev-ref HEAD)"

# Get back to the base repo.
cd $RD

# Clone regression tests framework.
git clone https://github.com/avast/retdec-regression-tests-framework
cd retdec-regression-tests-framework

# Checkout the same branch if possible.
git checkout "$RD_BRANCH" || git checkout master

echo "RetDec RT Framework: $(git rev-parse --abbrev-ref HEAD)"
