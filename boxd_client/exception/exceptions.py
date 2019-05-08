#!/usr/bin/env python
# -*- coding: utf-8 -*-


class BoxdError(Exception):
    """
    Raised when something wrong when send requests to rpc node
    """
    pass


class ValidationError(BoxdError):
    """
    Raised when something does not pass a validation check
    """
    pass


class InsufficientBalanceError(BoxdError):
    """
    Raised when the balance is insufficient for transfering
    """
    pass
