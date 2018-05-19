ssh $1 'rm -r /tmp/chewy'
ssh $1 'sudo killall python3'
scp -rq ./*.py $1:/tmp/
scp -rq ./chewy $1:/tmp/
ssh -t $1 'docker stop chewy; docker rm chewy; docker run --cap-add=ALL --name chewy --network wpasupplicant-net --ip 172.23.0.112 -v /tmp:/tmp -it chewy python3 /tmp/run.py; sleep 1; docker ps -a'
#ssh -t $1 'cd /tmp; sudo python3 run.py'
