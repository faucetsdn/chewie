ssh $1 'mkdir /tmp/chewie'
scp Dockerfile.chewie $1:/tmp/chewie/
ssh $1 'docker image build -t chewie -f /tmp/chewie/Dockerfile.chewie .'
ssh $1 'docker network create -d macvlan --subnet=172.23.0.0/16 wpasupplicant-net'