## Next-gen TUF client for Python

This package provides modules for TUF client implementers.

**tuf.ngclient.Updater** is a class that implements the client workflow
described in the TUF specification (see
https://theupdateframework.github.io/specification/latest/#detailed-client-workflow)

**tuf.ngclient.FetcherInterface** is an abstract class that client
implementers can implement a concrete class of in order to reuse their
own networking/download libraries -- a Requests-based implementation is
used by default.

This package:
* Aims to be a clean, easy-to-validate reference client implementation
  written in modern Python
* At the same time aims to be the library of choice for anyone
  implementing a TUF client in Python: light-weight, easy to integrate
  and with minimal required dependencies
* Is still under development but is planned to become the default client
  in this implementation (i.e., the older `tuf.client` will be deprecated
  in the future)
