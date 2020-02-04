# paloalto_xml-keyword-search
XML keyword search utility for Palo Alto Networks firewall and Panorama

This script will allow a user to pull a config from
Panorama/firewall once authenticated, then search for a keyword
string, and return the xpath containing the string if the it
was found. The output is separated by xpaths where the string
was found in the tag's attributes and where the string was
found in the tag's text. You will then have the option to view
children of the tag in the xpath.
