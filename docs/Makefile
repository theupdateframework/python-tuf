.PHONY: clean help html kramdown open xml2rfc
.DEFAULT_GOAL := help

OPEN=$(word 1, $(wildcard /usr/bin/xdg-open /usr/bin/open /bin/echo))
MKD := tuf-rfc.md
HTML := tuf-rfc.html
XML := tuf-rfc.xml
TXT := tuf-rfc.txt

clean: ## Remove the generated files
	@rm -rf $(HTML) $(XML) $(TXT) .refcache/

help: ## Print this message and exit
	@echo "\033[1;37mRequires 'gem install kramdown-rfc2629' and 'apt-get install xml2rfc'\033[0m" && \
		awk 'BEGIN {FS = ":.*?## "} /^[0-9a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

html: kramdown ## Convert the XML into HTML 
	@xml2rfc --html $(XML) $(HTML)

kramdown: ## Convert the Markdown into XML
	@kramdown-rfc2629 $(MKD) > $(XML)

open: html ## Open the HTML in a browser
	@$(OPEN) $(HTML)

xml2rfc: kramdown ## Convert the XML into RFC plaintext
	@xml2rfc $(XML) $(TXT)
