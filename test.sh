#!/bin/bash

ASN_LIST_FILENAME='force-include-asns.txt'

for s in `cut -d"#" -f1 $ASN_LIST_FILENAME`; do
    whois -h whois.radb.net -- "-K -T route -i origin $s" | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}(\/[0-9]{1,2})?"
done