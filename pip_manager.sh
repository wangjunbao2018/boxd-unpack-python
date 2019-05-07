#!/bin/sh

# install dependicies
pip install wheel
pip install twine

# remove old versions
rm dist/boxd*

# package
python setup.py sdist
python setup.py bdist_wheel

# upload
# Before do this step, update .pypirc in ~/.pypirc
twine upload dist/*
# twine upload --repository-url https://test .pypi.org/legacy/  dist/*
