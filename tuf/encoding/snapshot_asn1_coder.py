"""
<Purpose>
  This module contains conversion functions (get_asn_signed and get_json_signed)
  for converting Snapshot metadata from TUF's standard Python dictionary
  metadata format (usually serialized as JSON) to an ASN.1 format that conforms
  to pyasn1 specifications and TUF's new ASN.1 specification.

<Functions>
  get_asn_signed(pydict_signed)
  get_json_signed(asn_signed)    # TODO: Rename to get_pydict_signed in all mods

"""
from __future__ import print_function
from __future__ import unicode_literals

from pyasn1.type import univ, tag

from tuf.encoding.metadata_asn1_definitions import *

import tuf.conf
import calendar
from datetime import datetime #import datetime


def get_asn_signed(pydict_signed):
  """
  Given a Python dictionary conformant to TUF's standard data specification for
  Snapshot metadata (tuf.formats.SNAPSHOT_SCHEMA), convert to the new ASN.1
  format for Snapshot metadata, which derives from Snapshot*.asn1.
  """

  json_fileinfos = pydict_signed['meta']

  target_role_fileinfos = TargetRoleFileInfos().subtype(
      implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
  number_of_target_role_files = 0
  root_fileinfo = None

  for filename, pydict_fileinfo in json_fileinfos.items():

    # TODO: Consider checking the file itself to determine format... but have
    # to make sure we only mess with the real root metadata role file. (Don't
    # accidentally hit other metadata files?)
    if filename == 'root.' + tuf.conf.METADATA_FORMAT:
      # If we're dealing with the root metadata file, we expect hashes and
      # length in addition to just filename and version.

      # TODO: Check if we've already added a root file. Raise error.
      # TODO: Add ASN1_Conversion
      root_fileinfo = RootRoleFileInfo().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
      root_fileinfo['filename'] = filename
      root_fileinfo['version'] = pydict_fileinfo['version']

      if 'length' not in pydict_fileinfo or 'hashes' not in pydict_fileinfo:
        # TODO: Better error
        raise tuf.Error('ASN1 Conversion failure for Snapshot role: given '
            'fileinfo for assumed root metadata file (filename: ' +
            repr(filename) + '), found either hashes or length missing.')

      root_fileinfo['length'] = pydict_fileinfo['length']

      hashes = Hashes().subtype(
          implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple, 4))
      number_of_hashes = 0

      for hashtype, hashval in pydict_fileinfo['hashes'].items():
        hash = Hash()
        hash['function'] = int(HashFunction(hashtype))
        hash['digest'] = BinaryData().subtype(explicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatConstructed, 1))
        hash['digest']['octetString'] = univ.OctetString(
            hexValue=hashval).subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 1))
        hashes[number_of_hashes] = hash
        number_of_hashes += 1

      root_fileinfo['hashes'] = hashes
      root_fileinfo['numberOfHashes'] = number_of_hashes


    else:
      # Otherwise (if we're not dealing with the fileinfo for the root metadata
      # file), we're dealing with a target role file (the main Targets role
      # file or a delegated Targets role file), so we only expect filename and
      # version.

      if 'length' in pydict_fileinfo or 'hashes' in pydict_fileinfo:
        # TODO: Better error
        raise tuf.Error('ASN1 Conversion failure for Snapshot role: given '
            'fileinfo for assumed Targets or delegated metadata file '
            '(filename: ' +repr(filename) + '), found either hashes or length, '
            'which are not expected in Snapshot for a Targets role file.')

      fileinfo = TargetRoleFileInfo()
      fileinfo['filename'] = filename
      fileinfo['version'] = pydict_fileinfo['version']
      target_role_fileinfos[number_of_target_role_files] = fileinfo
      number_of_target_role_files += 1

  # Loop complete, all fileinfo (root, targets, any delegated targets)
  # loaded into target_role_fileinfos and root_fileinfo.

  if len(target_role_fileinfos) < 1:
    raise tuf.Error('ASN1 Conversion failure for Snapshot role: Found no '
        'Targets role file info entries or conversion failed for all fileinfo '
        'for Targets role files.')

  if root_fileinfo is None:
    raise tuf.Error('ASN1 Conversion failure for Snapshot role: Found no '
        'Root role file info entry or conversion failed for Root fileinfo.')


  snapshot_metadata = SnapshotMetadata().subtype(implicitTag=tag.Tag(
      tag.tagClassContext, tag.tagFormatConstructed, 2))

  snapshot_metadata['numberOfTargetRoleFiles'] = number_of_target_role_files
  snapshot_metadata['targetRoleFileInfos'] = target_role_fileinfos
  snapshot_metadata['rootRoleFileInfo'] = root_fileinfo


  # Construct the 'signed' entry in the Snapshot metadata file, in ASN.1.
  asn_signed = Signed().subtype(implicitTag=tag.Tag(
      tag.tagClassContext, tag.tagFormatConstructed, 0))

  asn_signed['type'] = int(RoleType('snapshot'))
  asn_signed['expires'] = calendar.timegm(datetime.strptime(
      pydict_signed['expires'], "%Y-%m-%dT%H:%M:%SZ").timetuple())
  asn_signed['version'] = pydict_signed['version']
  asn_signed['body'] = SignedBody().subtype(explicitTag=tag.Tag(
      tag.tagClassContext, tag.tagFormatConstructed, 3))
  asn_signed['body']['snapshotMetadata'] = snapshot_metadata


  return asn_signed





def get_json_signed(asn_metadata):
  """
  Given an ASN.1 object conforming to the new ASN.1 metadata definitions
  derived from Snapshot*.asn1, return a Python dictionary containing the same
  information, conformant to TUF's standard data specification for Snapshot
  metadata (tuf.formats.SNAPSHOT_SCHEMA).
  TUF internally does not use the ASN.1, converting it in and out of the
  standard Python dictionary formats defined in tuf.formats.
  """
  pydict_signed = {}

  # TODO: Normalize this function's interface: the asn_metadata given is
  # actually both 'signed' and 'signatures', which is strange since the
  # get_asn_signed function takes only the contents of the 'signed' entry, and
  # this function only returns the contents of a corresponding 'signed' entry.
  # (It is confusingly inconsistent to take the full object, return a converted
  # partial object, and have parallel naming and placement with a function that
  # takes and returns a partial object.)
  # This change has to percolate across all modules, however.
  asn_signed = asn_metadata['signed'] # This should be the argument instead of asn_metadata.

  # Should check this from the ASN, but... the ASN definitions don't actually
  # USE a type, so I'm entirely basing the type encoded on the filename. This
  # is bad, I think. Could it be a security issue to not sign the metadata type
  # in there? The metadata types are pretty distinct, but... it's still best to
  # fix this at some point.
  pydict_signed['_type'] = 'Snapshot'

  pydict_signed['expires'] = datetime.utcfromtimestamp(
    asn_signed['expires']).isoformat()+'Z'

  pydict_signed['version'] = int(asn_signed['version'])


  # Next, extract the fileinfo for each role file described in the ASN.1
  # Snapshot metadata.

  snapshot_metadata = asn_signed['body']['snapshotMetadata']

  number_of_target_role_files = int(
      snapshot_metadata['numberOfTargetRoleFiles'])
  asn_target_fileinfos = snapshot_metadata['targetRoleFileInfos']

  pydict_fileinfos = {}

  # Copy the Targets and delegated roles fileinfos:
  for i in range(number_of_target_role_files):
    asn_role_fileinfo = asn_target_fileinfos[i]
    filename = str(asn_role_fileinfo['filename'])
    pydict_fileinfos[filename] = {'version': int(asn_role_fileinfo['version'])}

  # Add in the Root role fileinfo:
  # In the Python dictionary format for Snapshot metadata, these all exist in
  # one dictionary.
  filename = str(snapshot_metadata['rootRoleFileInfo']['filename'])
  version = int(snapshot_metadata['rootRoleFileInfo']['version'])
  length = int(snapshot_metadata['rootRoleFileInfo']['length'])

  if filename in pydict_fileinfos:
    raise tuf.Error('ASN1 Conversion failure for Snapshot role: duplicate '
        'fileinfo entries detected: filename ' + str(filename) + ' identified '
        'both as Root role and Targets role in Snapshot metadata.')

  # Populate the hashes in the fileinfo describing the Root role.
  hashes = {}
  for i in range(snapshot_metadata['rootRoleFileInfo']['numberOfHashes']):
    asn_hash_info = snapshot_metadata['rootRoleFileInfo']['hashes'][i]

    # This is how we'd extract the name of the hash function from the
    # enumeration (namedValues) that is in the class (HashFunction), indexed by
    # the underlying "value" of asn_hash_info. The [0] at the end selects
    # the string description from a 2-tuple of e.g. ('sha256', 1), where 1 is
    # the value in the enum.
    # TODO: Should probably make this its own function. The following should
    # work:
    #   def translate_pyasn_enum_to_value(asn_enum_value):
    #     return asn_enum_value.namedValues[asn_enum_value][0]
    #
    hashtype = asn_hash_info['function'].namedValues[asn_hash_info['function']][0]
    hashval = asn_hash_info['digest']['octetString'].prettyPrint()  # TODO: "prettyPrint()" is probably not the way to go long-term.

    if not hashval.startswith('0x'):
      raise tuf.Error('ASN1 Conversion failure for Snapshot role: Given hash '
        'value in root role info in Snapshot for hash type ' + str(hashtype) +
        ' does not start with "0x".')
    hashval = hashval[2:] # Skip the '0x' header on the hash.

    hashes[hashtype] = hashval

  # Finally, add all the information gathered about the Root role.
  pydict_fileinfos[filename] = {
      'version': version,
      'length': length,
      'hashes': hashes}


  pydict_signed['meta'] = pydict_fileinfos

  return pydict_signed
