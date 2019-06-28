#!/bin/bash

CHEWIEHOME=`dirname $0`"/../.."
echo $CHEWIEHOME

for i in chewie test ; do find $CHEWIEHOME/$i/ -type f -name [a-z]*.py ; done
