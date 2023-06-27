# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Implementation of content addressable targets"""
import os
import sys
import inspect
from abc import ABC, abstractmethod
from typing import Optional
import requests

class Adapter(ABC):
    """Abstract class for content addressable systems"""

    @staticmethod
    @abstractmethod
    def scheme_name() -> str:
        """Return the scheme of the URI.
        
        Used to find out the correct adapter of a target file.
        """
        raise NotImplementedError

    @abstractmethod
    def fetch_target(self, target_dir: str) -> str:
        """Download the target file and return the target directory.
        
        Different adapters have different methods to fetch a file from its ecosystem.
        """
        raise NotImplementedError
    
    @abstractmethod
    def find_target_in_local_cache(self, target_dir: str) -> str:
        """Check whether the target file exists in the local cache.
        
        If found, return the location of the file.
        """
        raise NotImplementedError

class IPFS(Adapter):
    """Implements Adapter for IPFS targets"""

    ipfs_gateway_url = 'http://127.0.0.1:8081/ipfs/'
    scheme = 'ipfs'

    def __init__(self, cid: str):
        self.cid = cid

    @staticmethod
    def scheme_name() -> str:
        return IPFS.scheme

    def fetch_target(self, target_dir: str) -> str:
        file_url = self.ipfs_gateway_url + self.cid
        response = requests.get(file_url, timeout=5)
        if response.status_code == 200:
            filepath = self._generate_target_file_path(target_dir)
            with open(filepath, 'wb') as file:
                file.write(response.content)
            
            return filepath

        print('Failed to retrieve file:', response.status_code)
        return ''
    
    def find_target_in_local_cache(self, target_dir: str) -> Optional[str]:
        filepath = self._generate_target_file_path(target_dir)
        if os.path.exists(filepath):
            return filepath
        
        return None
    
    def _generate_target_file_path(self, target_dir: str) -> str:
        # TODO: Add the correct extension to the file name using Content-Type response header.
        file_name = self.cid
        return os.path.join(target_dir, file_name)

def get_adapter_class(scheme: str) -> Adapter:
    """Return the class of the provided scheme"""
    classType = Adapter
    subclasses = []
    classes = inspect.getmembers(sys.modules[__name__], inspect.isclass)
    for name, obj in classes:
        if (obj is not classType) and (classType in inspect.getmro(obj)):
            subclasses.append((obj, name))

    for cls, name in subclasses:
        if cls.scheme_name() == scheme:
            return cls
        
    return None