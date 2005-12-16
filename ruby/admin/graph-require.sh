#!/usr/bin/env bash

OUTPUT_FILE="deps.png"

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
matches = [(file, dep) for (file, dep)
           in parse_require.findall(file('require.txt').read())
           if re.match('(yadis|openid)($|/)', dep)
          ]
g = pydot.graph_from_edges(matches, directed=True)
g.write_png('$OUTPUT_FILE')
EOF
