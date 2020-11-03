#!/bin/sh
CLI_LOCATION=~/.local/dependency-check-1.2.11
CLI_SCRIPT=$CLI_LOCATION/bin/dependency-check.sh
NVD_PATH=$1/$(date -I -d $2)
NVD=file://$NVD_PATH
shift 2 # We've used the first two params. The rest go to CLI_SCRIPT.
$CLI_SCRIPT --cveUrl20Base $NVD/nvdcve-2.0-%d.xml.gz \
    --cveUrl12Base $NVD/nvdcve-%d.xml.gz \
    --cveUrl20Modified $NVD/nvdcve-2.0-Modified.xml.gz \
    --cveUrl12Modified $NVD/nvdcve-Modified.xml.gz \
    --data $NVD_PATH $@