ssh $1 'mkdir /tmp/wpasupplicant'
scp Dockerfile.wpasupplicant $1:/tmp/wpasupplicant/
ssh $1 'docker image build -t wpasupplicant -f /tmp/wpasupplicant/Dockerfile.wpasupplicant .'
#ssh $1 'docker network create --subnet 172.23.0.0/16 wpasupplicant-net'
ssh $1 'docker network create -d macvlan --subnet=172.23.0.0/16 wpasupplicant-net'
# need to enable /sys/devices/virtual/net/br0/bridge/multicast_querier
#bridge_id=`docker network inspect wpasupplicant-net -f "{{.Id}}"`
#bridge_name=br-${bridge_id:0:12}
# no permissions to set this?!
#ssh $1 'echo 1 | sudo tee /sys/devices/virtual/net/${bridge_name}/bridge/multicast_querier'
#ssh $1 'echo 0 | sudo tee /sys/devices/virtual/net/${bridge_name}/bridge/multicast_snooping'
#ssh $1 'echo 0 | sudo tee /sys/devices/virtual/net/${bridge_name}/bridge/multicast_router'