# -*- coding: utf-8 -*- 
"""
# Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
# 
#  This file was generated and any changes will be overwritten.
"""

from __future__ import unicode_literals
from ..model.thumbnail import Thumbnail

from .entity import Entity

class ThumbnailSet(Entity):
    def __init__(self, prop_dict={}):
        self._prop_dict = prop_dict

    @property
    def large(self):
        """
        Gets and sets the large
        
        Returns: 
            :class:`Thumbnail<microsoft.graph.model.thumbnail.Thumbnail>`:
                The large
        """
        if "large" in self._prop_dict:
            if isinstance(self._prop_dict["large"], GraphObjectBase):
                return self._prop_dict["large"]
            else:
                self._prop_dict["large"] = Thumbnail(self._prop_dict["large"])
                return self._prop_dict["large"]

        return None

    @large.setter
    def large(self, val):
        self._prop_dict["large"] = val

    @property
    def medium(self):
        """
        Gets and sets the medium
        
        Returns: 
            :class:`Thumbnail<microsoft.graph.model.thumbnail.Thumbnail>`:
                The medium
        """
        if "medium" in self._prop_dict:
            if isinstance(self._prop_dict["medium"], GraphObjectBase):
                return self._prop_dict["medium"]
            else:
                self._prop_dict["medium"] = Thumbnail(self._prop_dict["medium"])
                return self._prop_dict["medium"]

        return None

    @medium.setter
    def medium(self, val):
        self._prop_dict["medium"] = val

    @property
    def small(self):
        """
        Gets and sets the small
        
        Returns: 
            :class:`Thumbnail<microsoft.graph.model.thumbnail.Thumbnail>`:
                The small
        """
        if "small" in self._prop_dict:
            if isinstance(self._prop_dict["small"], GraphObjectBase):
                return self._prop_dict["small"]
            else:
                self._prop_dict["small"] = Thumbnail(self._prop_dict["small"])
                return self._prop_dict["small"]

        return None

    @small.setter
    def small(self, val):
        self._prop_dict["small"] = val

    @property
    def source(self):
        """
        Gets and sets the source
        
        Returns: 
            :class:`Thumbnail<microsoft.graph.model.thumbnail.Thumbnail>`:
                The source
        """
        if "source" in self._prop_dict:
            if isinstance(self._prop_dict["source"], GraphObjectBase):
                return self._prop_dict["source"]
            else:
                self._prop_dict["source"] = Thumbnail(self._prop_dict["source"])
                return self._prop_dict["source"]

        return None

    @source.setter
    def source(self, val):
        self._prop_dict["source"] = val

