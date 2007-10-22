#!/usr/bin/env bash

OUTPUT_FILE="deps.jpg"

if [ ! "$1" ] ; then
  echo "Usage: graph-require.sh <lib_directory> [output_filename]"
  exit 1
fi

if [ "$2" ] ; then
  OUTPUT_FILE=$2
fi

grep -r '^ *require ['"'"'"]' $1 > require.txt

python <<EOF
import re
import pydot
import sys

parse_require = re.compile(
    '\\\\blib/([^:]+).rb: *require ["\\']([^"\\']+)[\\'"]\$',
    re.MULTILINE)
matches = parse_require.findall(file('require.txt').read())
g = pydot.graph_from_edges(matches, directed=True)
g.write_jpeg('$OUTPUT_FILE')
EOF
