#scp bird.conf $1:/tmp/
ssh $1 'docker stop hostapd; docker rm hostapd; docker run --name hostapd --network hostapd-net --ip 172.27.0.111'
#-v /tmp/bird.conf:/etc/bird/bird.conf -v /tmp/bird:/run/bird --ip 172.25.0.111 -d osrg/bird /usr/sbin/bird -d; sleep 1; docker ps -a'