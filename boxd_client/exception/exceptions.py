#!/usr/bin/env python
# -*- coding: utf-8 -*-


class ValidationError(Exception):
    """
    Raised when something does not pass a validation check
    """
    pass


class BoxdError(Exception):
    """
    Raised when something wrong when send requests to rpc node
    """
    pass


