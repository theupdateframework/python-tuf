# Use Google Python style guide with minimal refinements

Technical Story: https://github.com/theupdateframework/python-tuf/issues/1128

## Context and Problem Statement

The Secure Systems Lab code style guide, which has been used for most of the
code base, has become outdated. Through the upcoming rewrite, we have the
chance to ignore consistency considerations with existing code style and can
choose a more standard and up-to-date style guide.

## Decision Drivers

* Flaws in original Secure Systems Lab style guide
* Curating a complete custom style guide is time consuming
* Well-established style rules lower contribution barrier
* Custom style is not supported by default in common tooling (i.e. editors
  and linters)

## Considered Options

* Use custom style guide
* Use Google style guide with refinements

## Decision Outcome

Chosen option: "Use Google style guide with refinements", because the Google
style guide is a comprehensive, well-established style guide that is mostly
based on PEP-8 and was accepted by everyone on the TUF team. There is no need
to replicate these recommendations. However, we do provide a very slim document
with additional refinements, in order to emphasize items the we consider
especially important, want to be handled differently, or in one specific way,
where the Google guide would allow multiple.

**Course of Action:**
* Follow existing style when working on existing code (files)
* Follow new style in any new code (files)
* Consider providing linter and formatter configuration (e.g. pylint, flake8,
  black, yapf) to enforce and facilitate new style


## Links
* [New Slim Secure Systems Lab style guide](https://github.com/secure-systems-lab/code-style-guidelines/pull/21)
* [Google Python style guide](https://google.github.io/styleguide/pyguide.html)
* [PEP 8](https://www.python.org/dev/peps/pep-0008/)
* [Issues in original Secure Systems Lab style guide](https://github.com/secure-systems-lab/code-style-guidelines/issues/20)
