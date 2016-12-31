# asn1

ASN.1 modules for UPTANE metadata and messages.
Please see the [Implementation Specification](https://docs.google.com/document/d/1noDyg2t5jB6y3R5-Y3TXXj1tocv_y24NjmOw8rAcaAc/edit?usp=sharing) for more details.

Careful when decoding ASN.1 messages: improper decoding may lead to arbitrary code execution, or denial-of-service attacks.
For example, see [CVE-2016-2108](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2108) and [attacks on a well-known ASN.1 compiler](http://arstechnica.com/security/2016/07/software-flaw-puts-mobile-phones-and-networks-at-risk-of-complete-takeover/).
