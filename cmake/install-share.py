#!/usr/bin/env python3

"""
Get RetDec share directory.
"""
import sys
import hashlib
import os
import shutil
import tarfile
import urllib.request

# Check arguments.
if len(sys.argv) != 2:
    print('ERROR: Unexpected number of arguments.')
    sys.exit(1)

###############################################################################

version_filename = 'version.txt'
arch_suffix = 'tar.xz'

sha256hash_ref = 'b54ba07e2f28143c9afe34a9d5b4114fb61f3c1175b9807caced471fec82001e'
version = '2018-02-08'

###############################################################################

arch_name = 'retdec-support' + '_' + version + '.' + arch_suffix

# Get install path from script options.
install_path = sys.argv[1]

share_dir = os.path.join(install_path, 'share')
share_retdec_dir = os.path.join(share_dir, 'retdec')
support_dir = os.path.join(share_retdec_dir, 'support')

arch_path = os.path.join(support_dir, arch_name)


###############################################################################

def cleanup():
    if os.path.exists(support_dir):
        for n in os.listdir(support_dir):
            p = os.path.join(support_dir, n)
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.unlink(p)


# Share directory exists.
if os.path.exists(support_dir):
    # Version file exists.
    if os.path.isfile(os.path.join(support_dir, version_filename)):
        with open(os.path.join(support_dir, version_filename)) as version_file:
            version_from_file = version_file.read().split('\n')[0]

        if version == version_from_file:
            print('%s already exists, version is ok' % support_dir)
            sys.exit(0)
        else:
            print('versions is not as expected -> replace with expected version')

    cleanup()

# Make sure destination directory exists.
os.makedirs(support_dir, exist_ok=True)

# Download archive
arch_url = 'https://github.com/avast-tl/retdec-support/releases/download/%s/%s' % (version, arch_name)
print('Downloading archive from %s ...' % arch_url)

try:
    urllib.request.urlretrieve(arch_url, arch_path)
except (urllib.request.HTTPError, urllib.request.URLError):
    print('ERROR: download failed')
    cleanup()
    sys.exit(1)

# Compute hash of the downloaded archive.
print('Verfifying archive\'s checksum ...')

sha256 = hashlib.sha256()
with open(arch_path, 'rb') as f:
    try:
        sha256.update(f.read())
    except IOError:
        print('ERROR: failed to compute the SHA-256 hash of the archive')
        cleanup()
        sys.exit(1)

sha256hash = sha256.hexdigest()

# Check that hash is ok.
if sha256hash != sha256hash_ref:
    print('ERROR: downloaded archive is invalid (SHA-256 hash check failed)')
    cleanup()
    sys.exit(1)

# Unpack archive.
print('Unpacking archive ...')
with tarfile.open(arch_path) as tar:
    try:
        tar.extractall(support_dir)
    except tarfile.ExtractError:
        print('ERROR: failed to unpack the archive')
        cleanup()
        sys.exit(1)

# Remove archive.
os.remove(arch_path)

print('RetDec support directory downloaded OK')
sys.exit(0)
