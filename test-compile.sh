#!/bin/bash

asn1c -EF CommonModule.asn1 MetadataModule.asn1 RootModule.asn1 TargetsModule.asn1 SnapshotModule.asn1 TimestampModule.asn1  TrustPinningModule.asn1

asn1c -EF CommonModule.asn1 TargetsModule.asn1 BootloaderModule.asn1

# TODO: May want to consider reorganizing how type definitions are shared.
asn1c -EF CommonModule.asn1 MetadataModule.asn1  RootModule.asn1 TargetsModule.asn1 SnapshotModule.asn1 TimestampModule.asn1 BootloaderModule.asn1 ApplicationModule.asn1
