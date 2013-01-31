"""
<Program Name>
  mirrors.py

<Author>
  Konstantin Andrianov
  Derived from original mirrors.py written by Geremy Condra.

<Started>
  March 12, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  This module extracts a list of mirror urls corresponding to the file type and
  the location of the file with respect to the base url.

"""

import os
import urllib

import tuf.util
import tuf.formats


def get_list_of_mirrors(file_type, file_path, mirrors_dict):
  """
  <Purpose>
    Gets a list of mirror urls from a mirrors dictionary, provided the type of
    the file and the path of the file with respect to the base url.

  <Arguments>
    file_type:
      Type of data needed for download, must correspond to one of the strings in
      the list ['meta', 'target', 'targets'].  'meta' for metadata file type or
      'target' or 'targets' for target file type.  It should correspond to
      FILETYPE_SCHEMA format.

    file_path:
      Path to the file.  For instance if the file is a target then we
      will have something like this: 'http://urlbase/targets_path/file_path'.
      It should correspond to RELPATH_SCHEMA format.

    mirrors_dict:
      A mirrors_dict object that corresponds to MIRRORDICT_SCHEMA, where the
      dict keys are strings and the dict values MIRROR_SCHEMA. An example format
      of MIRROR_SCHEMA:

    {'url_prefix':
     'metadata_path': 'metadata/'
     'targets_path': 'targets/'
     'confined_target_paths': ['targets/release1', ...]
     'custom': {...}}

    The 'custom' field is optional.

  <Exceptions>
    tuf.Error on unknown file type.
    tuf.FormatError on bad argument.

  <Return>
    List of mirror urls corresponding to the file_type and file_path.  If no
    match is found, empty list is returned.

  """

  # Checking if all the arguments have appropriate format.
  tuf.formats.RELPATH_SCHEMA.check_match(file_path)
  tuf.formats.MIRRORDICT_SCHEMA.check_match(mirrors_dict)
  tuf.formats.NAME_SCHEMA.check_match(file_type)

  # Reference to 'path_in_confined_paths' function.
  in_confined = tuf.util.path_in_confined_paths

  list_of_mirrors = []
  for mirror_name, mirror_info in mirrors_dict.items():
    if file_type == 'meta':
      base = mirror_info['url_prefix']+'/'+mirror_info['metadata_path']

    else:
      targets_path = mirror_info['targets_path']
      full_filepath = os.path.join(targets_path, file_path)
      if not in_confined(full_filepath, mirror_info['confined_target_paths']):
        continue
      base = mirror_info['url_prefix']+'/'+mirror_info['targets_path']

    # urllib.quote(string) replaces special characters in string using the %xx
    # escape.  This is done to avoid parsing issues of the URL on the server
    # side.
    file_path = urllib.quote(file_path)
    url = base+'/'+file_path
    list_of_mirrors.append(url)

  return list_of_mirrors
