#!/bin/bash

./clean.sh
asn1c -pdu=auto CommonModule.asn1 MetadataModule.asn1 RootModule.asn1 TargetsModule.asn1 SnapshotModule.asn1 TimestampModule.asn1  TrustPinningModule.asn1
mv Makefile.am.sample Makefile
make
