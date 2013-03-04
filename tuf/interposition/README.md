## How to interpose

```python
import tuf.interposition
tuf.interposition.configure()
```

### Option one

```python
tuf.interposition.interpose()
urllib.urlopen( 'http://example.com/path/to/document' )
urllib.urlretrieve( 'http://example.com/path/to/document' )
urllib2.urlopen( 'http://example.com/path/to/document' )
tuf.interposition.go_away()
```

### Option two

```python
@tuf.interposition.open_url
def method( self, url, ... )
```

## Interposition configuration

### Example of a configuration JSON object

```javascript
{
    "network_locations": {
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
            ])
        }
    }
}
```

"target_paths" is optional: If you do not tell TUF to selectively match paths
with regular expressions, TUF will work over any path under the given network
location. However, if you do specify it, you are then telling TUF how to
transform a specified path into another one, and TUF will *not* recognize any
unspecified path for the given network location.
