#!/bin/bash

./clean.sh
asn1c -pdu=auto CommonModule.asn1 TimeServerModule.asn1
mv Makefile.am.sample Makefile
make
