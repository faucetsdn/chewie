ssh $1 'mkdir /tmp/hostapd'
scp Dockerfile.hostapd $1:/tmp/hostapd/
ssh $1 'docker image build -t hostapd -f /tmp/hostapd/Dockerfile.hostapd .'
ssh $1 'docker network create --subnet 172.27.0.0/16 hostapd-net'