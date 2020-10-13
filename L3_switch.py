# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

from ryu.lib.packet import in_proto
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub

from operator import attrgetter
from ryu.topology.api import get_switch,get_link
from ryu.topology import event,switches
import time
import logging

app_manager.LOG.setLevel(logging.ERROR)
packet_count = 0
byte_count = 0 
proto = ''

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
         
        #test
        self.datapaths={}
        self.monitor_thread = hub.spawn(self._monitor)
        #self.topology_api_app = self
        self.switchs ={}
        self.links = {}
        self.logger.setLevel(logging.INFO)

    #test monitor
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
            	self._request_stats(dp)
            time.sleep(1)
            #hub.sleep(1)

    def _request_stats(self,datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath,0,ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply,MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        global packet_count
        global byte_count
        # self.logger.info('datapath         '
                        # 'in-port  eth-dst           '
                        # 'out-port packets  bytes')
        self.logger.info(' packets   bytes')
        # self.logger.info('---------------- '
                        # '-------- ----------------- '
                        # '-------- -------- --------')
        for stat in body:#sorted([flow for flow in body if flow.priority == 100],
                        #  key=lambda flow: (flow.match['in_port'],
                        #                    flow.match['eth_dst'])):
            #self.logger.info('%016x %8x %17s %8x %8d %8d',
            #                 ev.msg.datapath.id,
            #                 stat.match['in_port'], stat.match['eth_dst'],
            #                 stat.instructions[0].actions[0].port,
            #                 stat.packet_count, stat.byte_count)
            self.logger.info('%8d %8d %s', stat.packet_count, stat.byte_count, stat.instructions)
            
	    #test drop the packet
            packet_count = stat.packet_count
            byte_count = stat.byte_count
            #global proto
            if stat.priority != 0:
                #if stat.duration_sec % 20 == 0:
                 #  flags=4  #OFPFF_RESET_COUNTS
                  # datapath = ev.msg.datapath
                  # self.mod_flow(datapath, command = datapath.ofproto.OFPFC_MODIFY, 
                    #   table_id = stat.table_id, match = stat.match, inst = stat.instructions, flags = 4)
                if stat.match['ip_proto'] == 17: #udp
                    if (packet_count >= 50000 and byte_count >= 300000): #packet_length>=60
                        datapath = ev.msg.datapath		
                        pri = 100
                        match = stat.match
                        actions = []
                        #self.add_flow(datapath, pri, match, actions)
                        self.mod_flow(datapath, command = datapath.ofproto.OFPFC_MODIFY, 
                            table_id = stat.table_id, actions = actions, match = match)
                if stat.match['ip_proto'] == 6: #tcp
                    if (packet_count >= 50000 and byte_count >= 300000): #packet_length>=60
                        datapath = ev.msg.datapath		
                        pri = 100
                        match = stat.match
                        actions = []
                        #self.add_flow(datapath, pri, match, actions)
                        self.mod_flow(datapath, command = datapath.ofproto.OFPFC_MODIFY, 
                            table_id = stat.table_id, actions = actions, match = match)
                if stat.match['ip_proto'] == 1: #icmp
                    if (packet_count >= 50000 and byte_count >= 300000): #packet_length>=60
                        datapath = ev.msg.datapath		
                        pri = 100
                        match = stat.match
                        actions = []
                        #self.add_flow(datapath, pri, match, actions)
                        self.mod_flow(datapath, command = datapath.ofproto.OFPFC_MODIFY, 
                            table_id = stat.table_id, actions = actions, match = match)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
   
    def mod_flow(self, dp, cookie=0, cookie_mask=0, table_id=0,
                 command=None, idle_timeout=0, hard_timeout=0,
                 priority=0xff, buffer_id=0xffffffff, match=None,
                 actions=None, inst_type=None, out_port=None,
                 out_group=None, flags=0, inst=None):

        if command is None:
            command = dp.ofproto.OFPFC_ADD

        if inst is None:
            if inst_type is None:
                inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS

            inst = []
            if actions is not None:
                inst = [dp.ofproto_parser.OFPInstructionActions(
                        inst_type, actions)]

        if match is None:
            match = dp.ofproto_parser.OFPMatch()

        if out_port is None:
            out_port = dp.ofproto.OFPP_ANY

        if out_group is None:
            out_group = dp.ofproto.OFPG_ANY

        m = dp.ofproto_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                         table_id, command,
                                         idle_timeout, hard_timeout,
                                         priority, buffer_id,
                                         out_port, out_group,
                                         flags, match, inst)

        dp.send_msg(m)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        pri = 100
        global packet_count
        global byte_count
        global proto
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
       
        #check IP protocol and create a match for IP
           if eth.ethertype == ether_types.ETH_TYPE_IP:
               ip = pkt.get_protocol(ipv4.ipv4)
               srcip = ip.src
               dstip = ip.dst
               
               protocol = ip.proto
               proto = protocol
               #if ICMP protocol
               if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(in_port=in_port,eth_src=src,eth_dst=dst,eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=dstip,ipv4_src=srcip,ip_proto=protocol)
               #if TCP protocol
               elif protocol == in_proto.IPPROTO_TCP:
                      t = pkt.get_protocol(tcp.tcp)
                      tsrcport = t.src_port
                      tdstport = t.dst_port
                      match = parser.OFPMatch(in_port=in_port,eth_src=src,eth_dst=dst,eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=dstip,ipv4_src=srcip,ip_proto=protocol,tcp_dst=tdstport)
               #if UDP protocol
               elif protocol == in_proto.IPPROTO_UDP:
                      u = pkt.get_protocol(udp.udp)
                      usrcport = u.src_port
                      udstport = u.dst_port
                      match = parser.OFPMatch(in_port=in_port,eth_src=src,eth_dst=dst,eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=dstip,ipv4_src=srcip,ip_proto=protocol,udp_dst=udstport)
                         
               # verify if we have a valid buffer_id, if yes avoid to send both
               # flow_mod & packet_out
               if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                   self.add_flow(datapath, pri, match, actions, msg.buffer_id)
                   return
               else:
                self.add_flow(datapath, pri, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)



#    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
#    def _port_stats_reply_handler(self, ev):
#        body = ev.msg.body

#        self.logger.info('datapath         port     '
#                         'rx-pkts  rx-bytes rx-error '
#                         'tx-pkts  tx-bytes tx-error')
#        self.logger.info('---------------- -------- '
#                         '-------- -------- -------- '
#                         '-------- -------- --------')
#        for stat in sorted(body, key=attrgetter('port_no')):
#            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
#                             ev.msg.datapath.id, stat.port_no,
#                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
#                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)

