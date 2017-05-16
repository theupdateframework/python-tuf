# Security

Generally, a software update system is secure if it can be sure that it knows about the latest available updates in a timely manner, any files it downloads are the correct files, and no harm results from checking or downloading files. The details of making this happen are complicated by various attacks that can be carried out against software update systems.

## Attacks and Weaknesses

The following are some of the known attacks on software update systems, including weaknesses that make attacks possible. In order to design a secure software update framework, these need to be understood and protected against. Some of these issues are or can be related depending on the design and implementation of a software update system.

* **Arbitrary software installation**. An attacker installs anything they want on the client system. That is, an attacker can provide arbitrary files in response to download requests and the files will not be detected as illegitimate. 

* **Rollback attacks**. An attacker presents a software update system with older files than those the client has already seen, causing the client to use files older than those the client knows about. 

* **Fast-forward attacks**.  An attacker arbitrarily increases the version numbers of project metadata files in the snapshot
metadata well beyond the current value, thus tricking a software update system into thinking any subsequent updates are trying
to rollback the package to a previous, out-of-date version. In some situations, such as those where there is a maximum possible
version number, the perpetrator could use a number so high that the system would never be able to match it with the one in the
snapshot metadata, and thus new updates could never be downloaded.

* **Indefinite freeze attacks**. An attacker continues to present a software update system with the same files the client has already seen. The result is that the client does not know that new files are available. 

* **Endless data attacks**. An attacker responds to a file download request with an endless stream of data, causing harm to clients (e.g. a disk partition filling up or memory exhaustion). 

* **Slow retrieval attacks**. An attacker responds to clients with a very slow stream of data that essentially results in the client never continuing the update process. 

* **Extraneous dependencies attacks**. An attacker indicates to clients that in order to install the software they wanted, they also need to install unrelated software. This unrelated software can be from a trusted source but may have known vulnerabilities that are exploitable by the attacker. 

* **Mix-and-match attacks**. An attacker presents clients with a view of a repository that includes files that did not exist together on the repository at the same time. This can result in, for example, outdated versions of dependencies being installed. 

* **Wrong software installation**. An attacker provides a client with a trusted file that is not the one the client wanted. 

* **Malicious mirrors preventing updates**. An attacker in control of one repository mirror is able to prevent users from obtaining updates from other, good mirrors. 

* **Vulnerability to key compromises**. An attacker who is able to compromise a single key or less than a given threshold of keys can compromise clients. This includes relying on a single online key (such as only being protected by SSL) or a single offline key (such as most software update systems use to sign files). 

## Design Concepts

The design and implementation of TUF aims to be secure against all of the above attacks. A few general ideas drive much of the security of TUF.

For the details of how TUF conveys the information discussed below, see the [Metadata documentation](METADATA.md).

## Trust

Trusting downloaded files really means trusting that the files were provided by some trusted party. Two frequently overlooked aspects of trust in a secure software update system are:

* Trust should not be granted forever. Trust should expire if it is not renewed.
* Compartmentalized trust. A trusted party should only be trusted for files that it is supposed to provide. 

## Mitigated Key Risk

Cryptographic signatures are a necessary component in securing a software update system. The safety of the keys that are used to create these signatures affects the security of clients. Rather than incorrectly assume that private keys are always safe from compromise, a secure software update system must strive to keep clients as safe as possible even when compromises happen.

Keeping clients safe despite dangers to keys involves:

* Fast and secure key replacement and revocation.
* Minimally trusting keys that are at high risk. Keys that are kept online or used in an automated fashion shouldn't pose immediate risk to clients if compromised.
* Supporting the use of multiple keys with threshold/quorum signatures trust. 

## Integrity

File integrity is important both with respect to single files as well as collections of files. It's fairly obvious that clients must verify that individual downloaded files are correct. Not as obvious but still very important is the need for clients to be certain that their entire view of a repository is correct. For example, if a trusted party is providing two files, a software update system should see the latest versions of both of those files, not just one of the files and not versions of the two files that were never provided together.

## Freshness

As software updates often fix security bugs, it is important for software update systems to be able to obtain the latest versions of files that are available. An attacker may want to trick a client into installing outdated versions of software or even just convince a client that no updates are available.

Ensuring freshness means to:

* Never accept files older than those that have been seen previously.
* Recognize when there may be a problem obtaining updates. 

Note that it won't always be possible for a client to successfully update if an attacker is responding to their requests. However, a client should be able to recognize that updates may exist that they haven't been able to obtain.

## Implementation Safety

In addition to a secure design, TUF also works to be secure against implementation vulnerabilities including those common to software update systems. In some cases this is assisted by the inclusion of additional information in metadata. For example, knowing the expected size of a target file that is to be downloaded allows TUF to limit the amount of data it will download when retrieving the file. As a result, TUF is secure against endless data attacks (discussed above). 
