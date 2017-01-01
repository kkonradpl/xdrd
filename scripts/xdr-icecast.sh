#!/bin/bash
BITRATE=144
FRAMESIZE=10
IP=127.0.0.1
PORT=8080
PASSWORD=yourpassword
MOUNT=/xdr.opus
RECONNECT=5

LOCKFILE=/tmp/xdr-icecast.pid
if [ -f $LOCKFILE ]; then
    echo "Another instance is already running."
    echo "If not, remove $LOCKFILE"
    exit 0
fi
echo $$ > $LOCKFILE
trap "{ rm -f $LOCKFILE; }" EXIT

while [ 1 ];
do
    gst-launch-1.0 \
    alsasrc ! \
    audio/x-raw,format=S16LE,rate=48000,channels=2 ! \
    opusenc bitrate=$((BITRATE*1000)) frame-size=$FRAMESIZE ! \
    oggmux max-delay=0 max-page-delay=0 ! \
    shout2send ip=$IP port=$PORT password=$PASSWORD mount=$MOUNT &
    
    GSTPID=$!
    trap "{ kill -SIGINT $GSTPID; rm -f $LOCKFILE; }" EXIT
    wait $GSTPID
    wait $GSTPID
    trap "{ rm -f $LOCKFILE; }" EXIT
    
    sleep $RECONNECT
done

