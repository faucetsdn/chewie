#!/bin/bash

CHEWIEHOME=`dirname $0`"/../.."
for i in chewie test ; do find $CHEWIEHOME/$i/ -type f -name [a-z]*.py ; done
