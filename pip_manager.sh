#!/bin/sh

# install dependicies
pip install wheel
pip install twine

# package
python setup.py sdist
python setup.py bdist_wheel

# upload
twine upload dist/*
# twine upload --repository-url https://test .pypi.org/legacy/  dist/*