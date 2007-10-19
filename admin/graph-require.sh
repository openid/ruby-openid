#!/usr/bin/env bash
grep -r '^ *require ['"'"'"]' lib/ > require.txt

python <<EOF
import re
import pydot
import sys

parse_require = re.compile(
    '\\\\blib/([^:]+).rb: *require ["\\']([^"\\']+)[\\'"]\$',
    re.MULTILINE)
matches = parse_require.findall(file('require.txt').read())
g = pydot.graph_from_edges(matches, directed=True)
g.write_jpeg('deps.jpg')
EOF
