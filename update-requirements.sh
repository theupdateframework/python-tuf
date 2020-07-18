#!/bin/bash

# bail on the first error
set -e

# exception for python 2.7
python2.7 -m pip install --user virtualenv
python2.7 -m virtualenv tuf-env-2.7
source tuf-env-2.7/bin/activate
pip install pip-tools
pip-compile --no-header -o requirements-2.7.txt requirements.txt
deactivate
rm -rf tuf-env-2.7

# create a pinned requirements file for each supported MINOR Python3 version
for v in 3.5 3.6 3.7 3.8; do
  python${v} -m venv tuf-env-${v}
  source tuf-env-${v}/bin/activate
  pip install pip-tools
  pip-compile --no-header -o requirements-${v}.txt requirements.txt
  deactivate
  rm -rf tuf-env-${v}
done;

# merge per-version files
sort -o requirements-pinned.txt -u requirements-?.?.txt

# remove per-version files
rm requirements-?.?.txt