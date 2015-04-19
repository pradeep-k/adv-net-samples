
from pox.core import core
import pox.lib.packet as pkt

log = core.getLogger()

def print_packet(packet):
    log.debug("======Packet details start=======")
    log.debug("Ethernet source port: %s", packet.src)
    log.debug("Ethernet destination port: %s", packet.dst)
    log.debug("Ethernet packet type: %s", pkt.ETHERNET.ethernet.getNameForType(packet.type))
    if packet.type == packet.IP_TYPE:
        ip = packet.payload
    	log.debug("IP source address: %s", ip.srcip)
    	log.debug("IP destination address: %s", ip.dstip)
	if ip.protocol == ip.TCP_PROTOCOL:
            tcp = ip.payload
    	    log.debug("Transport protocol is: TCP")
    	    log.debug("TCP source port number: %s", tcp.srcport)
    	    log.debug("TCP destination port number: %s", tcp.dstport)
	elif ip.protocol == ip.UDP_PROTOCOL:
            udp = ip.payload
    	    log.debug("Transport protocol is: UDP")
    	    log.debug("UDP source port number: %s", udp.srcport)
    	    log.debug("UDP destination port number: %s", udp.dstport)
		 
    log.debug("======Packet details end========")
