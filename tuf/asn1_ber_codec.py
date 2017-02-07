"""
<Program Name>
  asn1_ber_codec.py

<Purpose>
  Provides functions to allow use of ASN.1/BER-encoded metadata with TUF.
"""
import tuf
import tuf.conf
import tuf.formats

try:
  # pyasn1 modules
  import pyasn1.codec.ber.encoder as p_ber_encoder
  import pyasn1.codec.ber.decoder as p_ber_decoder
  import pyasn1.type.tag as p_type_tag

  # Uptane/TUF data specification modules that convert ASN.1 to JSON and back.
  import uptane.encoding.rootmetadata as root_asn1_spec # Must pull out of Uptane.
  import uptane.encoding.snapshotmetadata as snapshot_asn1_spec # Must pull out of Uptane.
  import uptane.encoding.timestampmetadata as timestamp_asn1_spec # Must pull out of Uptane.
  import uptane.encoding.targetsmetadata as targets_asn1_spec # Must pull out of Uptane.
  import uptane.encoding.metadataverificationmodule as metadata_asn1_spec

  # This maps metadata type ('_type') to the module that lays out the
  # ASN.1 format for that type.
  SUPPORTED_ASN1_METADATA_MODULES = {
      'root': root_asn1_spec,
      'snapshot': snapshot_asn1_spec,
      'timestamp': timestamp_asn1_spec,
      'targets': targets_asn1_spec}

except ImportError:
  logger.warning('Minor: pyasn1 library not found. Proceeding using JSON only.')
  PYASN1_EXISTS = False

else:
  PYASN1_EXISTS = True





def ensure_valid_metadata_type_for_asn1(metadata_type):
  if metadata_type not in SUPPORTED_ASN1_METADATA_MODULES:
    # TODO: Choose/make better exception class.
    raise tuf.Error('This is not one of the metadata types configured for '
        'translation from JSON to BER. Type of given metadata: ' +
        repr(metadata_type) + '; types accepted: ' +
        repr([t for t in SUPPORTED_ASN1_METADATA_MODULES])) # TODO: <~> Kill this list comprehension. Make nicer.





def convert_signed_ber_to_bersigned_json(ber_data):
  """
  Convert the given ber_data to a Python dictionary representation consistent
  with TUF's typical JSON encoding.

  The 'signed' portion will be a JSON-style (essentially Python dict)
  translation of the ber data's 'signed' portion. Likewise for the 'signatures'
  portion. The result will be a dict containing a 'signatures' section that has
  signatures over not what is in the 'signed' section, but rather over a
  different format and encoding of what is in the 'signed' section. Please take
  care.

  """

  if not PYASN1_EXISTS:
    raise tuf.Error('Request was made to load a BER file, but the required '
        'pyasn1 library failed to import.')

  # "_signed" here refers to the portion of the metadata that will be signed.
  # The metadata is divided into "signed" and "signature" portions. The
  # signatures are signatures over the "signed" portion. "json_signed" below
  # is actually not signed - it is simply the portion that will be put into
  # the "signed" section - the portion to be signed. The nomenclature is
  # unfortunate....
  asn_metadata = p_ber_decoder.decode(
      ber_data, asn1Spec=metadata_asn1_spec.Metadata())[0] # why 0? Magic.

  # asn_metadata here now has three components, indexed by integer 0, 1, 2.
  # 0 is the signed component (Signed())
  # 1 i the numberOfSignatures component (Length())
  # 2 is the signatures component (Signatures())

  asn_signed_metadata = asn_metadata[0]

  # TODO: <~> The 'signed' component here should probably already be BER, since
  # that is what the signature is over. Because this would entail some changes
  # changes to the ASN.1 data specifications in metadataverificationmodule.py,
  # I'm not doing this yet (though I expect to).
  # So, for the time being, if we wanted to check the signature, we'd have to
  # encode this thing into BER again.
  # ber_signed_metadata = p_ber_encoder.encode(asn_signed)


  # Now we have to figure out what type of metadata the ASN.1 metadata is
  # so that we can use the appropriate spec to convert it back to JSON.

  # (Even though this takes asn_metadata, it only uses asn_metadata[0],
  # asn_signed_metadata....)
  asn_type_data = asn_signed_metadata[0] # This is the RoleType info, a class.

  # This is how we'd extract the name of the type from the enumeration that is
  # in the class (namedValues), indexed by the underlying "value" of
  # asn_type_data.
  # We call lower() on it because I don't care about the casing, which has
  # varied somewhat in TUF history, and I don't want casing to ruin this
  # detection.
  metadata_type = asn_type_data.namedValues[asn_type_data._value][0].lower()

  # Make sure it's a supported type of metadata for ASN.1 to Python dict
  # translation. (Throw an exception if not.)
  ensure_valid_metadata_type_for_asn1(metadata_type)

  # Handle for the corresponding module.
  relevant_asn_module = SUPPORTED_ASN1_METADATA_MODULES[metadata_type]

  # Convert into the basic Python dict we use in the JSON encoding.
  json_signed = relevant_asn_module.get_json_signed(asn_metadata)

  # Extract the signatures from the ASN.1 representation.
  asn_signatures = asn_metadata[2]
  json_signatures = []

  for asn_signature in asn_signatures:
    import pdb; pdb.set_trace()
    json_signatures.append({
        'keyid': str(asn_signature['keyid']),
        # TODO: <~> See if it's possible to tweak the definition of 'method' so that str(method) returns what we want rather here than the enum, so that we don't have to do make this weird enum translation call?
        'method': asn_signature['method'].namedValues[asn_signature['method']._value][0], #str(asn_signature['method']),
        'sig': str(asn_signature['value'])})

  return {'signatures': json_signatures, 'signed': json_signed}




def convert_signed_metadata_to_ber(
    signed_metadata, private_key=None, resign=False, only_signed=False):
  """
  Normal behavior ("resign" (re-sign) parameter being False) converts the
  basic Python dictionary format of signed_metadata provided into ASN.1 and
  encodes it as BER, returning the resulting BER encoding of the given metadata.

  "_signed" here refers to the portion of the metadata that will be signed.
  The metadata is divided into "signed" and "signature" portions. The
  signatures are signatures over the "signed" portion. "json_signed" below
  is actually not signed - it is simply the portion that will be put into
  the "signed" section - the portion to be signed. The nomenclature is
  unfortunate....
  TODO: Better variable and function naming.

  <Arguments>
    signed_metadata
      Role metadata and signature(s) over it.
      A dictionary with keys 'signed' and 'signatures'.
      signed_metadata must conform to tuf.formats.SIGNABLE_SCHEMA.
      Further, the 'signed' entry in signed_metadata must conform to
      tuf.formats.ANYROLE_SCHEMA.

    resign
      ("re-sign"). Normally False, resulting in the signatures in
      signed_metadata being formatted as ASN.1 and encoded as BER, but otherwise
      preserved.
      If resign is instead True, any signatures provided are
      discarded, and a new signature is generated. This new signature will be
      over the BER encoding of the data provided in signed_metadata['signed'].
      In other words, 'signed' will first be converted into ASN.1 and then
      encoded as BER, and a signature will be made using the given private_key,
      over that BER encoding.
      If the given signatures are already over BER encoding before reaching
      this point (as may happen in the current design), then you will not
      need this to be True....
      # TODO: <~> Revise above comment after you're finished.

    private_key
      This should be left out (None) unless resign is True, in which case
      private_key must conform to tuf.formats.ANYKEY_SCHEMA, containing a
      private key, specifically. It will be used to re-sign the metadata
      provided in signed_metadata['signed'].
      Such a key can be imported, for example, through the
      tuf.repository_tool.import_*_private_key() functions.

    only_signed
      Default False. If this is set to True, instead of returning the BER
      encoding of the full {'signed': {"abc..."}, 'signatures': [{"xyz..."}]}
      object, the BER encoding of only the 'signed' entry will be returned
      {"abc..."}.

  <Returns>
    By default (only_signed=False, resign=False), the returned value is the BER
    encoding of the full signed_metadata dictionary.

    If only_signed is True, the returned value is the BER encoding of only the
    'signed' entry in the signed_metadata dictionary.

    Otherwise, if resign is True, the returned value is the BER encoding of the
    full signed_metadata dictionary, but with the 'signatures' entry
    discarded and rebuilt anew with a new signature over the BER ENCODING of the
    'signed' entry in the signed_metadata dictionary.

  """
  # Make sure that if and only if the re-sign ('resign') parameter is True, a
  # private_key has been provided.
  tuf.formats.BOOLEAN_SCHEMA.check_match(resign)
  if resign != (private_key is not None):
    raise tuf.Error('Inconsistent arguments: a private key should be provided '
        'to convert_signed_json_to_signed_ber if and only if the resign '
        'argument is True.')

  if only_signed and resign:
    raise tuf.Error('Inconsistent arguments: request to re-sign metadata in a '
        'new encoding and then throw those same new signatures away.')


  if private_key is not None:
    tuf.formats.ANYKEY_SCHEMA.check_match(private_key)
    # TODO: Note that this does not confirm that it is specifically a private key.
    # Consider checking that. (Best way is to have an additional SCHEMA in
    # tuf.formats and use that.)

  tuf.formats.SIGNABLE_SCHEMA.check_match(signed_metadata)
  tuf.formats.ANYROLE_SCHEMA.check_match(signed_metadata['signed'])

  json_signed = signed_metadata['signed']

  # Force lowercase for metadata type because some TUF versions have been
  # inconsistent in the casing of metadata types ('targets' vs 'Targets').
  metadata_type = json_signed['_type'].lower()

  # Ensure that the type is one of the supported metadata types, for which
  # a module exists that translates it to and from an ASN.1 format.
  ensure_valid_metadata_type_for_asn1(metadata_type)

  # Handle for the corresponding module.
  relevant_asn_module = SUPPORTED_ASN1_METADATA_MODULES[metadata_type]
  asn_signed = relevant_asn_module.get_asn_signed(json_signed) # Python3 breaks here.

  if only_signed:
    # If the caller doesn't want any signatures included in the returned
    # BER object, then we need go no further and may encode what we already
    # have.
    ber_signed = p_ber_encoder.encode(asn_signed)
    return ber_signed


  if resign:

    # Encode the ASN.1 as BER using pyasn1.
    ber_signed = p_ber_encoder.encode(asn_signed)

    # This hashing is redundant and temporary. Eventually, the hash will
    # consistently be performed in securesystemslib/keys.py in the
    # create_signature() function, so we shouldn't be taking a hash here.
    # For the time being, I do this so that it always uses a hash even for ed25519
    # and also so that the canonicalization that is currently called by
    # create_signature() doesn't choke on the BER I want to sign.
    hash_of_ber = hashlib.sha256(ber_signed).hexdigest()

    # Now sign the metadata. (This signs a cryptographic hash of the metadata.)
    # The returned value is a basic Python dict writable into JSON.
    # This is a signature over the hash of the BER encoding.
    pydict_signatures = [tuf.keys.create_signature(private_key, hash_of_ber)]#ber_signed)

  else:
    pydict_signatures = signed_metadata['signatures']

  # Create a pyASN.1 object of custom class Signatures, containing some
  # unknown sorcery to specify types.
  # TODO: <~> Understand and clarify!
  # The following documents tagging in pyasn1:
  #   http://www.red-bean.com/doc/python-pyasn1/pyasn1-tutorial.html#1.2
  asn_signatures_list = metadata_asn1_spec.Signatures().subtype(
      implicitTag=p_type_tag.Tag(p_type_tag.tagClassContext,
      p_type_tag.tagFormatSimple, 2))

  # Now convert each Python dictionary-style signature into an ASN.1 signature
  # and stick those into the ASN.1 list just created.
  # Note that a Signatures() object has no append() method, so we clumsily
  # iterate through with index 'i'.
  i = 0 # Index for iterating through asn
  for pydict_sig in pydict_signatures:

    # Construct an ASN.1 representation of the signature and populate it.
    asn_sig = metadata_asn1_spec.Signature()
    asn_sig['keyid'] = pydict_sig['keyid']
    # Because 'method' is an enum, extacting the string value is a bit messier.
    asn_sig['method'] = int(metadata_asn1_spec.SignatureMethod(
        pydict_sig['method'].encode('ascii')))
    asn_sig['value'] = pydict_sig['sig']

    # Add to the Signatures() list.
    asn_signatures_list[i] = asn_sig # has no append method
    i += 1

  # Now construct an ASN.1 representation of the signed/signatures-encapsulated
  # metadata, populating it.
  metadata = metadata_asn1_spec.Metadata()
  metadata['signed'] = asn_signed #considering using ber_signed instead - requires changes
  metadata['signatures'] = asn_signatures_list # TODO: Support multiple sigs, or integrate with TUF.
  metadata['numberOfSignatures'] = len(asn_signatures_list)

  # Encode our new (py)ASN.1 object as BER (Basic Encoding Rules).
  return p_ber_encoder.encode(metadata)



