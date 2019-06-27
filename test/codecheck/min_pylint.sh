#!/bin/bash

CHEWIEHOME=`dirname $0`"/../.."
PYTHONPATH=$CHEWIEHOME

MINRATING=8.0

lintfile=`mktemp`.lint

for f in $* ; do
    PYTHONPATH=$PYTHONPATH pylint --rcfile=/dev/null $f > $lintfile
    rating=`cat $lintfile | grep -ohE "rated at [0-9\.]+" | sed "s/rated at //g"`
    echo pylint $f: $rating
    failing=$(bc <<< "$rating < $MINRATING")
    if [ "$failing" -ne 0 ]; then
        cat $lintfile
        echo "$rating below min ($MINRATING), results in $lintfile"
        exit 1
    fi
    rm $lintfile
done

exit 0