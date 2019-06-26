#!/bin/bash

if [ -z "$CHEWIE_ROOT" ]; then
    CDIR=`dirname $0`
    CHEWIE_ROOT=$(realpath ${CDIR}"/../..")
fi
if [ -z "$MIN_LINT_RATING" ]; then
    MIN_LINT_RATING=8.0
fi

PYTHONPATH=$CHEWIE_ROOT
lintfile=`mktemp`.lint

for f in $* ; do
    PYTHONPATH=$PYTHONPATH pylint --rcfile=/dev/null $f > $lintfile
    rating=`cat $lintfile | grep -ohE "rated at [0-9\.]+" | sed "s/rated at //g"`
    echo pylint $f: $rating
    failing=$(bc <<< "$rating < $MIN_LINT_RATING")
    if [ "$failing" -ne 0 ]; then
        cat $lintfile
        echo "$rating below min ($MIN_LINT_RATING), results in $lintfile"
        exit 1
    fi
    rm $lintfile
done

exit 0