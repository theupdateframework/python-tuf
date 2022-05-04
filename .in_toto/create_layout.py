"""Script to generate two generic in-toto layouts to verify wheel & sdist independently.

The layouts define two steps and an inspection:
- step 1 (tag): used as initial reference for the source code
- step 2 (build): requires its inputs to match the tagged sources
- inspect: requires the actual final product available to the verifier, i.e. sdist or
  wheel, to match the outputs of the build step (this is, where the two layouts differ).

In addition the layouts define, which keys are authorized to provide attestations, and
how many are required:
- tag: any one maintainer
- build: at least two of maintainers and online build job


Usage:
    # Create signing key pair for CD ('filepath' must be CD_KEY_PATH defined below)
    python -c 'import securesystemslib.interface as i;\
        i.generate_and_write_ed25519_keypair_with_prompt(filepath="cd_key")'

    # Create unsigned layout files 'wheel.layout' and 'sdist.layout'
    python create_layout.py

    # Sign layout with maintainer key
    in-toto-sign --gpg <gpg key id> -f wheel.layout
    in-toto-sign --gpg <gpg key id> -f sdist.layout

"""
from in_toto.models.layout import Inspection, Layout, Step
from in_toto.models.metadata import Metablock
from securesystemslib.interface import import_ed25519_publickey_from_file

MAINTAINER_KEYIDS = [
    "e9c059ec0d3264fab35f94ad465bf9f6f8eb475a",  # Justin Cappos
    "1343c98fab84859fe5ec9e370527d8a37f521a2f",  # Jussi Kukkonen
    "f3ff39b659ed00e877084a18b4934539a71e38cd",  # Trishank Karthik Kuppusamy
    "08f3409fcf71d87e30fbd3c21671f65cb74832a4",  # Joshua Lock
    "8ba69b87d43be294f23e812089a2ad3c07d962e8",  # Lukas Puehringer
]
CD_KEY_PATH = "cd_key"
CD_KEY = import_ed25519_publickey_from_file(f"{CD_KEY_PATH}.pub")

for build in ["sdist", "wheel"]:
    layout = Layout()
    # FIXME: What is a good expiration period?
    layout.set_relative_expiration(months=12)

    # Add public keys for verifying in-toto attestion signatures to layout
    # Requires 'MAINTAINER_KEYIDS' in your local keychain
    layout.add_functionary_key(CD_KEY)
    layout.add_functionary_keys_from_gpg_keyids(MAINTAINER_KEYIDS)

    # Define tag step, used as initial reference, to be signed by any maintainer.
    tag_step = Step(name="tag")
    tag_step.pubkeys = MAINTAINER_KEYIDS
    tag_step.threshold = 1

    # Define build step and require materials to match the sources recorded in tag step.
    # Moreover, a threshold of 2 requires there to be at least 2 agreeing build
    # attestations, e.g. from cd and from a maintainer.
    build_step = Step(name=build)
    build_step.pubkeys = [CD_KEY["keyid"]] + MAINTAINER_KEYIDS
    build_step.threshold = 2
    build_step.add_material_rule_from_string("MATCH * WITH MATERIALS FROM tag")
    build_step.add_material_rule_from_string("DISALLOW *")

    # Define inspection and require the actual final product available to the verifier,
    # i.e. sdist or wheel, to match the product recorded by the build step.
    # (see in-toto/docs#27 for a discussion about dummy inspections)
    dummy_inspection = Inspection(name="final-product")
    dummy_inspection.set_run_from_string("true")
    dummy_inspection.add_material_rule_from_string(
        f"MATCH * WITH PRODUCTS IN dist FROM {build}"
    )
    dummy_inspection.add_material_rule_from_string("DISALLOW *")

    layout.steps = [tag_step, build_step]
    layout.inspect = [dummy_inspection]
    metablock = Metablock(signed=layout)
    metablock.dump(f"{build}.layout")
