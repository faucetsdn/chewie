#! /bin/bash

cp -r /chewie-src/etc/wpasupplicant/ /tmp/wpasupplicant || exit 1
PYTHONPATH=/chewie-src/ pytest -v /chewie-src/test/integration/test_*.py || exit 1
