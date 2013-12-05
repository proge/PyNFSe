#!/bin/bash

for x in *.xsd; do generateDS.py -o $(echo $x | sed -e "s/.xsd/.py/") $x; done

