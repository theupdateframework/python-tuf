# Use Markdown Architectural Decision Records

* Status: accepted
* Date: 2020-10-20

Technical Story: https://github.com/theupdateframework/python-tuf/issues/1141

## Context and Problem Statement

We want to record architectural decisions made in this project.
Which format and structure should these records follow?

## Considered Options

* [MADR](https://adr.github.io/madr/) 2.1.2 – The Markdown Architectural Decision Records
* Formless – No conventions for file format and structure

## Decision Outcome

Chosen option: "MADR 2.1.2", because

* Implicit assumptions should be made explicit.
  Design documentation is important to enable people understanding the decisions
  later on.
* The MADR structure is comprehensible and facilitates usage & maintenance.
