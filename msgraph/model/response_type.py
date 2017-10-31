# -*- coding: utf-8 -*- 
"""
# Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
# 
#  This file was generated and any changes will be overwritten.
"""

from enum import Enum

class ResponseType(Enum):
    """The Enum ResponseType."""
    #none
    none = "0"
    #organizer
    organizer = "1"
    #tentatively Accepted
    tentativelyAccepted = "2"
    #accepted
    accepted = "3"
    #declined
    declined = "4"
    #not Responded
    notResponded = "5"
