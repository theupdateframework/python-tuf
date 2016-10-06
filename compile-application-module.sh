#!/bin/bash

./clean.sh
# TODO: May want to consider reorganizing how type definitions are shared.
asn1c -pdu=auto CommonModule.asn1 MetadataModule.asn1  RootModule.asn1 TargetsModule.asn1 SnapshotModule.asn1 TimestampModule.asn1 TimeServerModule.asn1 BootloaderModule.asn1 ApplicationModule.asn1
mv Makefile.am.sample Makefile
make
