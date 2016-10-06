#!/bin/bash

./clean.sh
asn1c -pdu=auto CommonModule.asn1 TargetsModule.asn1 TimeServerModule.asn1 BootloaderModule.asn1
mv Makefile.am.sample Makefile
make
