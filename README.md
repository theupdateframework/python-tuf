<div align="center">
  <a href="https://theupdateframework.com/">
    <img src="https://github.com/cncf/artwork/blob/main/projects/tuf/horizontal/white/tuf-horizontal-white.svg" height="200" alt="TUF" style="background-color:white"/>
  </a>
</div>


# <div align="center">A Framework for Securing Software Update Systems</div>

![Build](https://github.com/theupdateframework/python-tuf/actions/workflows/ci.yml/badge.svg)
[![Coveralls](https://coveralls.io/repos/theupdateframework/python-tuf/badge.svg?branch=develop)](https://coveralls.io/r/theupdateframework/python-tuf?branch=develop)
[![Docs](https://readthedocs.org/projects/theupdateframework/badge/)](https://theupdateframework.readthedocs.io/)
[![CII](https://bestpractices.coreinfrastructure.org/projects/1351/badge)](https://bestpractices.coreinfrastructure.org/projects/1351)
[![PyPI](https://img.shields.io/pypi/v/tuf)](https://pypi.org/project/tuf/)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/theupdateframework/python-tuf/badge)](https://api.securityscorecards.dev/projects/github.com/theupdateframework/python-tuf)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## Table of Contents

- [Introduction](#introduction)
- [About The Update Framework](#about-the-update-framework)
- [Key Features](#key-features)
- [Documentation](#documentation)
- [Installation](#installation)
- [Contact](#contact)
- [Security Issues and Bugs](#security-issues-and-bugs)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Introduction

The Update Framework (TUF) is a framework for secure content delivery and updates. It protects against various types of supply chain attacks and provides resilience to compromise. This repository is a **reference implementation** written in Python. It is intended to conform to version 1.0 of the [TUF specification](https://theupdateframework.github.io/specification/latest/).

Python-TUF provides the following APIs:
  
- [`tuf.api.metadata`](https://theupdateframework.readthedocs.io/en/latest/api/tuf.api.html): A "low-level" API designed to provide easy and safe access to TUF metadata and to handle (de)serialization from/to files.
  
- [`tuf.ngclient`](https://theupdateframework.readthedocs.io/en/latest/api/tuf.ngclient.html): A client implementation built on top of the metadata API.
  
- `tuf.repository`: A repository library also built on top of the metadata API. This module is currently not considered part of python-tuf stable API.

The reference implementation strives to be a readable guide and demonstration for those working on implementing TUF in their own languages, environments, or update systems.

---

## About The Update Framework

The Update Framework (TUF) is a design that helps developers maintain the security of a software update system, even against attackers that compromise the repository or signing keys. TUF provides a flexible specification defining functionality that developers can use in any software update system or re-implement to fit their needs.

TUF is hosted by the [Linux Foundation](https://www.linuxfoundation.org/) as part of the [Cloud Native Computing Foundation](https://www.cncf.io/) (CNCF) and is utilized in production by various tech companies and open-source organizations. A variant of TUF called [Uptane](https://uptane.github.io/) is used to secure over-the-air updates in automobiles.

For more information about TUF, visit [TUF's website](https://theupdateframework.com/).

---

## Key Features

- **Robust Security**: TUF ensures the security of software update systems, even in the face of compromise or supply chain attacks. It employs a variety of cryptographic techniques to guarantee the integrity and authenticity of software updates.
- **Flexible Specification**: TUF provides a flexible specification that developers can adapt to fit their specific software update system requirements. This allows for easy integration into existing systems and promotes interoperability.
- **Production Usage**: TUF is utilized in production by various tech companies and open-source organizations, demonstrating its reliability and effectiveness in real-world scenarios.
- **Variant Support**: TUF's variant, Uptane, is specifically designed to secure over-the-air updates in automobiles, showcasing its versatility and applicability across different domains.

---

## Documentation

- [Introduction to TUF's Design](https://theupdateframework.io/overview/): Provides an overview of TUF's design principles and goals.
- [The TUF Specification](https://theupdateframework.github.io/specification/latest/): Offers detailed documentation on TUF's specification, explaining its various components and functionalities.
- [Developer Documentation](https://theupdateframework.readthedocs.io/), including [API Reference](https://theupdateframework.readthedocs.io/en/latest/api/api-reference.html) and [Instructions for Contributors](https://theupdateframework.readthedocs.io/en/latest/CONTRIBUTING.html)
- [Governance](https://github.com/theupdateframework/python-tuf/blob/develop/docs/GOVERNANCE.md): Outlines the governance model for the reference implementation of TUF.
- [Miscellaneous Docs](https://github.com/theupdateframework/python-tuf/tree/develop/docs): Additional documentation covering various aspects of TUF implementation and usage.
- [Python-TUF Development Blog](https://theupdateframework.github.io/python-tuf/): Provides insights, updates, and news related to Python-TUF development.

---

## Installation

For installation instructions, please visit the [installation page](https://theupdateframework.readthedocs.io/en/latest/INSTALLATION.html).

---

## Contact

### Mailing List
- [![Mailing List](https://img.shields.io/badge/Mailing%20List-Subscribe-brightgreen)](https://groups.google.com/forum/?fromgroups#!forum/theupdateframework)
  - Join our low-volume mailing list for discussions, announcements, and updates.

### CNCF Slack
- [![CNCF Slack](https://img.shields.io/badge/CNCF%20Slack-%23tuf-brightgreen)](https://slack.cncf.io/)
  - Join the #tuf channel on CNCF Slack for real-time discussions and support.

Questions, feedback, and suggestions are welcomed on our mailing list or the CNCF Slack channel.

---

## Security Issues and Bugs

[![Security](https://img.shields.io/badge/Security%20Issues-SECURITY.md-red)](docs/SECURITY.md)

If you encounter any security issues or bugs, please refer to the [security policy](docs/SECURITY.md) for reporting and guidelines.

---

## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This work is dual-licensed and distributed under the (1) MIT License and (2) Apache License, Version 2.0. Please see [LICENSE-MIT](https://github.com/theupdateframework/python-tuf/blob/develop/LICENSE-MIT) and [LICENSE](https://github.com/theupdateframework/python-tuf/blob/develop/LICENSE) for more details.

---

## Acknowledgements

This project is hosted by the Linux Foundation under the Cloud Native Computing Foundation. TUF's early development was managed by members of the [Secure Systems Lab](https://ssl.engineering.nyu.edu/) at [New York University](https://engineering.nyu.edu/). We appreciate the efforts of all [maintainers and emeritus maintainers](https://github.com/theupdateframework/python-tuf/blob/develop/docs/MAINTAINERS.txt), as well as the contributors Konstantin Andrianov, Kairo de Araujo, Ivana Atanasova, Geremy Condra, Zane Fisher, Pankhuri Goyal, Justin Samuel, Tian Tian, Martin Vrachev, and Yuyu Zheng who significantly contributed to TUF's reference implementation. Maintainers and Contributors are governed by the [CNCF Community Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md).

This material is based upon work supported by the National Science Foundation under Grant Nos. CNS-1345049 and CNS-0959138. Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the National Science Foundation.

---

## <div align="center"> The Update Framework (TUF) is a CNCF graduated project </div>

<div align="center">
  <a href="https://www.cncf.io/">
    <img src="https://github.com/cncf/artwork/blob/main/other/cncf/horizontal/white/cncf-white.png" height="150" alt="TUF" style="background-color:white"/>
  </a>
</div>

---

[![](https://img.shields.io/badge/Move%20to%20Top-%E2%86%91%20Back%20to%20Top-blue)](#a-framework-for-securing-software-update-systems)

