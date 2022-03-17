#!/bin/bash

FORCE_ASNS_LIST_FILENAME='force-include-asns.txt'
FORCE_NETS_LIST_FILENAME='force-include-nets.txt'

TMP_ADDRS='.tmpaddr'
LAST_COMMIT='.lastcommit'

update_git() {
    if [ -d ./.z-i ]; then
        rm -rf ./.z-i
    fi
    git clone --filter=blob:none --no-checkout --depth 1 git@github.com:zapret-info/z-i.git .z-i
    git -C .z-i sparse-checkout set dump.csv nxdomain.txt
# 	git -C .z-i fetch --depth 1
# 	git -C .z-i reset --hard origin/master
# #        git -C .z-i pull --depth 1 --allow-unrelated-histories
#     else
#         git clone --filter=blob:none --no-checkout --depth 1 git@github.com:zapret-info/z-i.git .z-i
#         git -C .z-i sparse-checkout set dump.csv nxdomain.txt
#     fi
}

garbage_collect() {
    echo;
    # if [ -d ./.z-i ]; then
    #     git -C .z-i reflog expire --expire=all --all
    #     git -C .z-i gc --prune=all
    # fi
}

exit_if_no_changes() {
    if [ -f $LAST_COMMIT ]; then
        current=$(git -C .z-i rev-parse HEAD)
        last=$(cat $LAST_COMMIT)
        if [ "$current" = "$last" ]; then
            echo "No changes detected since last run"
            exit 0
        fi
    fi
}
mark_complete() {
    current=$(git -C .z-i rev-parse HEAD)
    echo "$current" > $LAST_COMMIT
}

extract_ips() {
    echo > $TMP_ADDRS

    # Force ASNs
    for s in `cut -d"#" -f1 $FORCE_ASNS_LIST_FILENAME`; do
        whois -h whois.radb.net -- "-K -T route -i origin $s" | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}(\/[0-9]{1,2})?" >> $TMP_ADDRS
    done

    # Force NETs
    cut -d"#" -f1 $FORCE_NETS_LIST_FILENAME | tr -d ' ' >> $TMP_ADDRS

    # Extract from RKN dumps
    cut -d";" -f1 .z-i/dump.csv | tr '|' '\n' |  tr -d ' ' >> $TMP_ADDRS

    # Cleanup and sort
    cat $TMP_ADDRS | sort | uniq | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}(\/[0-9]{1,2})?" > .v4.addr

    # Summarize NETs
    python3 rkn-summarize.py
}

resolve_hostnames() {
    python3 resolve-hostnames.py
}

reconfigure_bird() {
    mv /etc/bird/ips.routes /etc/bird/ips.routes.bak
    mv /etc/bird/hostname.routes /etc/bird/hostname.routes.bak
    cp .ips.routes /etc/bird/ips.routes
    cp .hostname.routes /etc/bird/hostname.routes
    cp .stats.prom /var/lib/prometheus/node-exporter/rkn-bypass.prom
    /etc/init.d/bird reload
}

resolve_hostnames
reconfigure_bird

update_git
exit_if_no_changes

extract_ips
reconfigure_bird

mark_complete
garbage_collect

exit 0
