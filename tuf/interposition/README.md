## Examples

```python
import tuf.interposition
# configuration is a JSON object in tuf.interposition.json
tuf.interposition.configure()
```

### Option one

```python
tuf.interposition.interpose()
# now you have TUF
url = 'http://example.com/path/to/document'
urllib.urlopen( url )
urllib.urlretrieve( url )
urllib2.urlopen( url )
tuf.interposition.go_away()
# now you do not have TUF
```

### Option two

```python
@tuf.interposition.open_url
def instancemethod( self, url, ... )
```

## Configuration

### Example of a configuration JSON object

```javascript
{
    "configurations": {
        "seattle.cs.washington.edu": {
            "repository_directory": "client/",
            "repository_mirrors" : {
                "mirror1": {
                    "url_prefix": "http://seattle-tuf.cs.washington.edu",
                    "metadata_path": "metadata",
                    "targets_path": "targets",
                    "confined_target_dirs": [ "" ]
                }
            },
            ("target_paths": [
                { ".*/(simple/\\w+)/$": "{0}/index.html" },
                { ".*/(packages/.+)$": "{0}" }
            ],
            "ssl_certificates": "cacert.pem")
        }
    }
}
```

TODO: Explain `network_locations`, `target_paths`, and the rest of the
parameters.

`target_paths` is optional: If you do not tell TUF to selectively match paths
with regular expressions, TUF will work over any path under the given network
location. However, if you do specify it, you are then telling TUF how to
transform a specified path into another one, and TUF will *not* recognize any
unspecified path for the given network location.

Unless any `url_prefix` begins with "https://", `ssl_certificates` is optional; it
must specify certificates bundled as PEM (RFC 1422).

## Limitations (at the time of writing)

- The entire `urllib` or `urllib2` contract is not honoured.
- Downloads are not thread safe.
- Uses some Python features (e.g. string formatting) not available in earlier versions (e.g. < 2.6).
- Uses some Python features (e.g. `urllib, urllib2, urlparse`) not available in later versions (e.g. >= 3).
