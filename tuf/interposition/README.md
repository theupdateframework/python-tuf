## How to interpose

    import tuf.interposition
    tuf.interposition.configure()

### Option one

    tuf.interposition.interpose()
    urllib.urlopen( 'http://example.com/path/to/document' )
    urllib.urlretrieve( 'http://example.com/path/to/document' )
    urllib2.urlopen( 'http://example.com/path/to/document' )
    tuf.interposition.go_away()

### Option two

    @tuf.interposition.open_url
    def method( self, url, ... )

## Interposition configuration
