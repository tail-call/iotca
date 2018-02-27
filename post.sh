#!/bin/sh
# Posts data to ACME server

ACME_URL="https://acme-v01.api.letsencrypt.org/acme"

usage ()
{
    echo "$0 <FILENAME> <PATH>"
    echo "PATH is along the lines of 'new-reg', 'new authz', etc"
}

if [[ -z "$1" || -z "$2" ]] ; then
    usage
    echo "Error: bad parameters"
    exit 1
fi

echo Posting to "$ACME_URL/$2" 
curl -d "@$1" -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     "$ACME_URL/$2" 
