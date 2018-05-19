ssh $1 'mkdir /tmp/chewy'
scp Dockerfile.chewy $1:/tmp/chewy/
ssh $1 'docker image build -t chewy -f /tmp/chewy/Dockerfile.chewy .'
ssh $1 'docker network create -d macvlan --subnet=172.23.0.0/16 wpasupplicant-net'