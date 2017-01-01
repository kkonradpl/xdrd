#!/bin/bash
LOCKFILE=/tmp/xdr-icecast.pid

if [ ! -f $LOCKFILE ]; then
	echo "Streaming is not running!"
	exit 0
fi
kill `cat $LOCKFILE`
