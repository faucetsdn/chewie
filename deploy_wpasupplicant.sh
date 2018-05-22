scp wpasupplicant.conf $1:/tmp/wpasupplicant/
ssh -t $1 'docker stop wpasupplicant;\
           docker rm wpasupplicant;\
           docker run --cap-add=ALL --name wpasupplicant \
           --network wpasupplicant-net --ip 172.23.0.111 \
           -v /tmp/wpasupplicant:/tmp -it wpasupplicant \
           wpa_supplicant -dd -c /tmp/wpasupplicant.conf\
           -i eth0 -D wired;\
           sleep 1; docker ps -a'
#ssh -t $1 'docker stop wpasupplicant; docker rm wpasupplicant; docker run --cap-add=ALL --name wpasupplicant --network wpasupplicant-net --ip 172.23.0.111 -v /tmp/wpasupplicant:/tmp -it wpasupplicant bash' #wpa_supplicant -dd -c /tmp/wpasupplicant.conf -i eth0 -D wired; sleep 1; docker ps -a'
#-v /tmp/bird.conf:/etc/bird/bird.conf -v /tmp/bird:/run/bird --ip 172.25.0.111 -d osrg/bird /usr/sbin/bird -d; sleep 1; docker ps -a'