## Examples

```python
import tuf.interposition
# Configurations are simply a JSON object which allows you to answer these questions:
# - Which network locations get intercepted?
# - Given a network location, which TUF mirrors should we forward requests to?
# - Given a network location, which paths should be intercepted?
# - Given a TUF mirror, how do we verify its SSL certificate?
tuf.interposition.configure()
```

### Option one

```python
from tuf.interposition import urllib_tuf as urllib
from tuf.interposition import urllib2_tuf as urllib2

url = 'http://example.com/path/to/document'
urllib.urlopen(url)
urllib.urlretrieve(url)
urllib2.urlopen(url)
```

### Option two

```python
@tuf.interposition.open_url
def instancemethod(self, url, ...):
  ...
```

## Configuration

A *configuration* is simply a JSON object which tells `tuf.interposition` which
URLs to intercept, how to transform them (if necessary), and where to forward
them (possibly over SSL) for secure responses via TUF.

By default, the configuration object is expected to be situated in the current
working directory in the file with the name "tuf.interposition.json". You may
change this like so:

```python
tuf.interposition.configure(filename="/path/to/json")
```

### Examples

#### Basic

```javascript
{
  // This is a required root object.
  "configurations": {
    // Which network location should we intercept?
    // Network locations may be specified as "hostname" or "hostname:port".
    "seattle.poly.edu": {
      // Where do we find the client copy of the TUF server metadata?
      "repository_directory": "client/",
      // Where do we forward the requests to seattle.poly.edu?
      "repository_mirrors" : {
        "mirror1": {
          // In this case, we forward them to http://tuf.seattle.poly.edu
          "url_prefix": "http://tuf.seattle.poly.edu",
          // You do not have to worry about these default parameters.
          "metadata_path": "metadata",
          "targets_path": "targets",
          "confined_target_dirs": [ "" ]
        },
        // You could specify more repository mirrors.
        ...
      }
    }
  },
  // You could specify more network locations.
  ...
}
```

*Network locations* must be unique across configurations; this restriction
prevents interposition cycles, amongst other things.

Note that, presently, a network request to a specified network location will be
intercepted no matter what its protocol scheme (e.g http, https) may be.

If you choose to specify `repository_directory` as a relative path, then how
would you determine its absolute path at runtime? You should then configure
interposition with this additional parameter:

```python
tuf.interposition.configure(parent_repository_directory="/path/to/parent/to/repository_directory")
```

#### Matching and transforming URL paths with regular expressions

Given a network location, you might want `tuf.interposition` to intercept only
URL paths that match certain patterns. A related problem is that you might wish
to transform a source path into another target path, perhaps because TUF might
not recognize it readily (e.g. it is an implicit reference to file) or because
you want to hide server-side changes from the client for its convenience. You
can solve both of these problems by matching and transforming URL paths with
regular expressions.

```javascript
{
  "configurations": {
    "pypi.python.org": {
      "repository_mirrors" : {
        "mirror1": {
            "url_prefix": "http://pypi.updateframework.com",
            ...
        },
        ...
      },
      ...,
      "target_paths": [
        { ".*/(simple/\\w+)/$": "{0}/index.html" },
        { ".*/(packages/.+)$": "{0}" }
      ]
    }
  }
}
```

In Javascript lingo, `target_paths` is an array of objects, wherein each object
has exactly a single property mapping the transformation of a *source* path
pattern S to a *target* path pattern T. Given a URL path U, `tuf.interposition`
will attempt to match U against every pattern S in order of appearance in this
array. If a match is found, then the
[groups](http://docs.python.org/2/library/re.html#match-objects) captured with S
will be applied to the [format
string](http://docs.python.org/2/library/string.html#string-formatting) T;
otherwise, or in case of an error, `tuf.interposition` will log a warning that
it will not interpose for U.

This brings us to the following important note. `target_paths` is optional: if
you do not configure a network location with this parameter, interposition will
work over *any* path under the given network location. However, if you do
specify this parameter, then you are implicitly telling `tuf.interposition` how
to transform a specified path into another one, and `tuf.interposition` will
*not* recognize any unspecified path for the given network location, *unless*
you add a wildcard regular expression like so:

```javascript
"target_paths": [
  ...,
  { "(.*)", "{0}" }
]
```

(Internally, this wildcard regular expression is added when `target_paths` is
left unspecified; this is why interposition will then apply to *any* path given
a specified network location.)

In the example above, we will apply the following transformations:

- "http://pypi.python.org/simple/Django/" => "http://pypi.updateframework.com/simple/Django/index.html"
- "http://pypi.python.org/packages/source/D/Django/Django-1.4.5.tar.gz" => "http://pypi.updateframework.com/packages/source/D/Django/Django-1.4.5.tar.gz"

(Actually, there is an implied "targets" root directory on the TUF server, but
we ignore it for pedagogical purposes.)

However, we will not match, and hence apply any transformation towards the
following URLs patterns, or interpose for them:

- "http://pypi.python.org/search"
- "http://pypi.python.org/serversig/(.+)"

Note: We are considering replacing this feature with a simpler, and hence more
provably secure, mechanism. Please follow issue
[#32](https://github.com/akonst/tuf/issues/32) for more details.

#### Mirror SSL certificate verification

For additional security, you may wish to configure a network location such that
a repository mirror must communicate over the HTTPS protocol. You may do this
by specifying the "https" protocol scheme in the `url_prefix` of a repository
mirror.

Furthermore, you may require `tuf.interposition` to verify the purported SSL
certificate of a repository mirror with the `ssl_certificates` parameter.

```javascript
{
  "configurations": {
    "pypi.python.org": {
      "repository_mirrors" : {
        "main": {
          "url_prefix": "https://pypi.updateframework.com",
          ...
        }
      },
      ...
      "ssl_certificates": "cacert.pem"
    }
  }
}
```

If any `url_prefix` begins with "https://", then `ssl_certificates` is a
required parameter; it must point to a file of
[certificates](http://docs.python.org/2/library/ssl.html#certificates) bundled
as [PEM](https://www.ietf.org/rfc/rfc1422).

If you choose to specify `ssl_certificates` as a relative path, then how
would you determine its absolute path at runtime? You should then configure
interposition with this additional parameter:

```python
tuf.interposition.configure(parent_ssl_certificates_directory="/path/to/parent/to/ssl_certificates")
```

## Applications

### Seattle + TUF

We have a demonstration of the [Seattle](https://seattle.poly.edu/)
software updater over TUF, which we expect to publish soon.

### PyPI + TUF + pip

We have a demonstration of the Python package manager, [pip, over
TUF](https://github.com/dachshund/pip/tree/tuf).

## Limitations (at the time of writing)

- The entire `urllib` or `urllib2` contract is not honoured.
- Downloads are not thread-safe.
- Uses some Python features (e.g. string formatting) that are not backwards-compatible (e.g. with Python < 2.6).
- Uses some Python features (e.g. `urllib, urllib2, urlparse`) that are not forwards-compatible (e.g. with Python >= 3).
