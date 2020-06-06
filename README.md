# paloalto_xml-keyword-search

This script will allow a user to pull a config from
Panorama/firewall, then search for a keyword
string, and return the xpath containing the string if any
were found. The output is separated by xpaths where the string
was found in the tag's attributes and where the string was
found in the tag's text. You will then have the option to view
children of the tag in the xpath.

You can optionally add ' --i' to your search query to do a case-insensitive search
  - Example: 'foobar --i' would match on foobar, FooBar, and FOOBAR
