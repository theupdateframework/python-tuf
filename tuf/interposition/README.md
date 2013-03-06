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
tuf.interposition.interpose()
# Now you have TUF...
url = 'http://example.com/path/to/document'
urllib.urlopen( url )
urllib.urlretrieve( url )
urllib2.urlopen( url )
tuf.interposition.go_away()
# ...and now you don't!
```

### Option two

```python
@tuf.interposition.open_url
def instancemethod( self, url, ... )
```

## Configuration

A *configuration* is simply a JSON object which tells `tuf.interposition` which
URLs to intercept, how to transform them (if necessary), and where to forward
them (possibly over SSL) for secure responses via TUF.

By default, the configuration object is expected to be situated in the current
working directory in the file with the name "tuf.interposition.json". You may
change this like so:

```python
tuf.interposition.configure( filename = "/path/to/json" )
```

### Examples

#### Basic

```javascript
{
    // This is a required root object.
    "configurations": {
        // Which network location should we intercept?
        // Network locations may be specified as "hostname" or "hostname:port".
        "seattle.cs.washington.edu": {
            // Where do we find the client copy of the TUF server metadata?
            "repository_directory": "client/",
            // Where do we forward the requests to seattle.cs.washington.edu?
            "repository_mirrors" : {
                "mirror1": {
                    // In this case, we forward them to http://tuf.seattle.cs.washington.edu
                    "url_prefix": "http://tuf.seattle.cs.washington.edu",
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
intercepted no matter what its protocol scheme (e.g http, https).

If you choose to specify "repository_directory" as a relative path, then how
would you determine its absolute path at runtime? No problem:

```python
tuf.interposition.configure(
    parent_repository_directory = "/path/to/parent/to/repository_directory"
)
```

#### Selecting target paths with regular expressions

```javascript
{
    "configurations": {
        "pypi.python.org": {
            ...,
            "target_paths": [
                { ".*/(simple/\\w+)/$": "{0}/index.html" },
                { ".*/(packages/.+)$": "{0}" }
            ]
        }
    }
}
```

`target_paths` is optional: If you do not tell TUF to selectively match paths
with regular expressions, TUF will work over *any* path under the given network
location.

However, if you do specify it, you are then telling TUF how to
transform a specified path into another one, and TUF will *not* recognize any
unspecified path for the given network location.

#### Mirror SSL certificate verification

```javascript
{
    "configurations": {
        "pypi.python.org": {
            "repository_mirrors" : {
                "main": {
                    "url_prefix": "https://pip.updateframework.com",
                    ...
                }
            },
            ...
            "ssl_certificates": "cacert.pem"
        }
    }
}
```

Unless any `url_prefix` begins with "https://", `ssl_certificates` is optional; it
must specify certificates bundled as PEM (RFC 1422).

```python
tuf.interposition.configure(
    parent_ssl_certificates_directory = "/path/to/parent/to/ssl_certificates"
)
```

## Limitations (at the time of writing)

- The entire `urllib` or `urllib2` contract is not honoured.
- Downloads are not thread safe.
- Uses some Python features (e.g. string formatting) that are not backwards-compatible (e.g. with Python < 2.6).
- Uses some Python features (e.g. `urllib, urllib2, urlparse`) that are not forwards-compatible (e.g. with Python >= 3).
