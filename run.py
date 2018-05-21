import socket
import struct
from select import select
from fcntl import ioctl
from netils import build_byte_string

from chewie.chewie import Chewie

#NETWORK_INTERFACE = "eth0"
#NETWORK_INTERFACE = "br-208d61c884fc"
#NETWORK_INTERFACE = "vethe8b890e"

credentials = {
    "user@example.com": "microphone"
}
chewie = Chewie("eth0", credentials)
chewie.run()

exit()

print("opening socket")
eapol_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x888e))
eapol_socket.bind((NETWORK_INTERFACE, 0))

# test packet = 0180c2000003001906eab88c888e01000005010100050100000000000000000000000000000000000000000000000000000000000000000000000000
# test src mac = 00:19:06:ea:b8:8c
# test dest mac = 01:80:c2:00:00:03
# src mac = 02:42:7b:79:87:7c
# dest mac = 02:42:ac:19:00:6f

# http://man7.org/linux/man-pages/man7/packet.7.html
# struct packet_mreq {
#                      int            mr_ifindex;    /* interface index */
#                      unsigned short mr_type;       /* action */
#                      unsigned short mr_alen;       /* address length */
#                      unsigned char  mr_address[8]; /* physical-layer address */
#                  };

SIOCGIFINDEX = 0x8933
ifname, ifindex = struct.unpack('16sI', ioctl(eapol_socket, SIOCGIFINDEX, struct.pack('16sI', NETWORK_INTERFACE.encode("utf-8"), 0)))
print("ifname: %s, ifindex: %d" % (ifname, ifindex))
SIOCGIFHWADDR = 0x8927
ifname, sa_family, hwaddr = struct.unpack('16sH6s',ioctl(eapol_socket, SIOCGIFHWADDR, struct.pack('16sH6s', ifname, 0, b"")))
print("ifname: %s, sa_family: %d, hwaddr: %s" % (ifname, sa_family, ":".join(["%02x" % x for x in hwaddr])))

print("listening to multicast group")
pae_group_addr = b"\x01\x80\xc2\x00\x00\x03"
PACKET_MR_MULTICAST = 0
PACKET_MR_PROMISC = 1
PACKET_MR_ALLMULTI = 2
mreq = struct.pack("IHH8s", ifindex, PACKET_MR_MULTICAST, len(pae_group_addr), pae_group_addr)
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
eapol_socket.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
print("sending packet")
identity_request1 = "888e01000005010100050100000000000000000000000000000000000000000000000000000000000000000000000000"
packet = pae_group_addr + hwaddr + build_byte_string(identity_request1)
eapol_socket.send(packet)
print("reading")
data = eapol_socket.recv(4096)
print("Got packet %s" % data)
# assume it's correct and send the same thing again
identity_request2 = "888e01000005010000050100000000000000000000000000000000000000000000000000000000000000000000000000"
print("sending request again")
packet = pae_group_addr + hwaddr + build_byte_string(identity_request2)
eapol_socket.send(packet)
data = eapol_socket.recv(4096)
print("Got packet %s" % data)
challenge = "888e01000016010100160410824788d693e2adac6ce15641418228cf"
print("sending challenge")
packet = pae_group_addr + hwaddr + build_byte_string(challenge)
eapol_socket.send(packet)
data = eapol_socket.recv(4096)
print("Got packet %s" % data)
success = "888e0100000403010004"
print("sending success")
packet = pae_group_addr + hwaddr + build_byte_string(success)
eapol_socket.send(packet)
eapol_socket.close()
