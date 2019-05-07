#!/usr/bin/env python

import pkg_resources
import sys
import warnings


if sys.version_info.major < 3:
    warnings.simplefilter("always", DeprecationWarning)
    warnings.warn(
        DeprecationWarning(
            "The `boxd-client` library supports for Python 2 and 3. For better development, please upgrade to Python 3."
        )
    )
    warnings.resetwarnings()


__version__ = pkg_resources.get_distribution("boxd-client").version