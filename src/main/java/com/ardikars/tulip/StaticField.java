/**
 * Copyright (C) 2017  Ardika Rommy Sanjaya
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.ardikars.tulip;

import com.ardikars.jxnet.*;
import com.ardikars.jxnet.exception.JxnetException;
import com.ardikars.jxnet.packet.Packet;
import com.ardikars.jxnet.packet.PacketHelper;
import com.ardikars.jxnet.packet.arp.ARP;
import com.ardikars.jxnet.packet.arp.ARPOperationCode;
import com.ardikars.jxnet.packet.ethernet.Ethernet;
import com.ardikars.jxnet.packet.ethernet.ProtocolType;
import com.ardikars.jxnet.util.AddrUtils;
import com.ardikars.jxnet.util.FormatUtils;
import com.ardikars.jxnet.util.Preconditions;

import java.nio.ByteBuffer;
import java.util.*;

public class StaticField {

    public static String source;
    public static int snaplen;
    public static int promisc;
    public static int immediate;
    public static int timeout;
    public static int optimize;

    public static volatile Pcap ARP_HANDLER;
    public static volatile Pcap ICMP_HANDLER;
    public static volatile Pcap ARP_PING_HANDLER;

    public static MacAddress CURRENT_MAC_ADDRESS;
    public static MacAddress CURRENT_GATEWAY_MAC_ADDRESS;
    public static Inet4Address CURRENT_INET4_ADDRESS;
    public static Inet4Address CURRENT_GATEWAY_ADDRESS;
    public static Inet4Address CURRENT_NETWORK_ADDRESS = Inet4Address.valueOf(0);
    public static Inet4Address CURRENT_NETMASK_ADDRESS = Inet4Address.valueOf(0);
    public static Map<Inet4Address, MacAddress> ARP_CACHE = new HashMap<Inet4Address, MacAddress>();
    public static Map<Inet4Address, Long> EPOCH_TIME = new HashMap<Inet4Address, Long>();

    public static long LOOP_TIME = 2000;

    public static long TIME = 60000;

    public static Random random = new Random();

    public static void initialize(String src, int snaplen, int promisc, int immediate, int to_ms, int optimize) throws Exception {

        Preconditions.CheckArgument(snaplen >= 1500 || snaplen <= 65535);
        Preconditions.CheckArgument(promisc == 1 || promisc == 0);
        Preconditions.CheckArgument(immediate == 1 || immediate == 0);
        Preconditions.CheckArgument(to_ms > 0);
        Preconditions.CheckArgument(optimize == 1 || optimize == 0);

        StringBuilder errbuf = new StringBuilder();

        String source = (src == null) ? getSource() : src;
        if (source == null) {
            throw new Exception("Unable to find network interface.");
        }

        StaticField.source = source;
        StaticField.snaplen = snaplen;
        StaticField.promisc = promisc;
        StaticField.immediate = immediate;
        StaticField.timeout = to_ms;
        StaticField.optimize = optimize;

        StaticField.CURRENT_INET4_ADDRESS = getCurrentInet4Address(source);
        if (StaticField.CURRENT_INET4_ADDRESS == null) {
            throw new Exception("Unable to get current ip address.");
        }

        StaticField.CURRENT_GATEWAY_ADDRESS = AddrUtils.GetGatewayAddress();
        if (StaticField.CURRENT_GATEWAY_ADDRESS == null) {
            throw new Exception("Unable to get current gateway address.");
        }

        StaticField.CURRENT_MAC_ADDRESS = MacAddress.fromNicName(source);
        if (StaticField.CURRENT_MAC_ADDRESS == null) {
            throw new Exception("Unable to get current mac address.");
        }

        if (Jxnet.PcapLookupNet(StaticField.source, StaticField.CURRENT_NETWORK_ADDRESS,
                StaticField.CURRENT_NETMASK_ADDRESS, errbuf) != 0) {
            throw new Exception("Unable to get current netmask and network address: " + errbuf.toString());
        }

        StaticField.ARP_HANDLER = openLive("arp");
        StaticField.ICMP_HANDLER = openLive("tcp");
        StaticField.ARP_PING_HANDLER = openLive("arp");

        if ((StaticField.CURRENT_GATEWAY_MAC_ADDRESS = getGwAddrFromArp()) == null) {
            throw new Exception("Unable to get current gateway Mac Address.");
        }

        System.out.println("Interface           : " + source);
        System.out.println("Address             : " + StaticField.CURRENT_INET4_ADDRESS + "" +
                " (" + StaticField.CURRENT_MAC_ADDRESS + ")");
        System.out.println("Gateway             : " + StaticField.CURRENT_GATEWAY_ADDRESS + "" +
                " (" + StaticField.CURRENT_GATEWAY_MAC_ADDRESS + ") ");
        System.out.println("Netmask             : " + StaticField.CURRENT_NETMASK_ADDRESS);
        System.out.println("Network Address     : " + StaticField.CURRENT_NETWORK_ADDRESS);

    }

    public static Pcap openOffline(String filter, String path) {
        return null;
    }

    public static Pcap openLive(String filter) throws Exception {

        StringBuilder errbuf = new StringBuilder();

        Pcap pcap = Jxnet.PcapCreate(StaticField.source, errbuf);
        if (pcap == null) {
            throw new Exception("Unable to open handler for " + StaticField.source);
        }

        if (Jxnet.PcapSetSnaplen(pcap, StaticField.snaplen) != 0) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            throw new Exception("Unable to set snaplen for the handler: " + err);
        }

        if (Jxnet.PcapSetPromisc(pcap, StaticField.promisc) != 0 ) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            throw new Exception("Unable to set promisc for the handler: " + err );
        }

        if (Jxnet.PcapSetImmediateMode(pcap, StaticField.immediate) != 0 ) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            throw new Exception("Unable to set promisc for the handler: " + err);
        }

        if (Jxnet.PcapSetTimeout(pcap, StaticField.timeout) != 0) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            throw new Exception("Unable to set promisc for the handler: " + err);
        }

        if (Jxnet.PcapActivate(pcap) != 0) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            throw new Exception(err);
        }

        if(Jxnet.PcapSetDirection(pcap, PcapDirection.PCAP_D_IN) != 0) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            throw new Exception("Unable to set direction for the handler: " + err);
        }

        BpfProgram fp = new BpfProgram();
        if (Jxnet.PcapCompile(pcap, fp, filter, StaticField.optimize,
                StaticField.CURRENT_NETMASK_ADDRESS.toInt()) != 0 ) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            throw new Exception("Unable to compile bpf: " + err);
        }

        if (Jxnet.PcapSetFilter(pcap, fp) != 0) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            throw new Exception("Unable to set filter: " + err);
        }

        return pcap;
    }

    public static Inet4Address getCurrentInet4Address(String source) {
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> pcapIf = new ArrayList<PcapIf>();
        if (Jxnet.PcapFindAllDevs(pcapIf, errbuf) != 0) {
            throw new JxnetException("Failed to get Ip Address from " + source);
        }
        for (PcapIf If : pcapIf) {
            if (If.getName().equals(source)) {
                for (PcapAddr addrs : If.getAddresses()) {
                    if (addrs.getAddr().getSaFamily() == SockAddr.Family.AF_INET) {
                        return Inet4Address.valueOf(addrs.getAddr().getData());
                    }
                }
                break;
            }
        }
        return null;
    }

    public static String getSource() {
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> pcapIfs = new ArrayList<PcapIf>();
        if (Jxnet.PcapFindAllDevs(pcapIfs, errbuf) != 0) {
            System.err.println(errbuf.toString());
            System.exit(0);
        }
        String source = null;
        for (PcapIf pcapIf : pcapIfs) {
            for (PcapAddr addr : pcapIf.getAddresses()) {
                if (addr.getAddr().getSaFamily() == SockAddr.Family.AF_INET &&
                        !Inet4Address.valueOf(addr.getAddr().getData()).equals(Inet4Address.LOCALHOST)
                        ) {
                    source = pcapIf.getName();
                    break;
                }
            }
        }
        return source;
    }

    public static MacAddress getGwAddrFromArp() {

        Packet arp = new ARP()
                .setHardwareType(DataLinkType.EN10MB)
                .setProtocolType(ProtocolType.IPV4)
                .setHardwareAddressLength((byte) 6)
                .setProtocolAddressLength((byte) 4)
                .setOperationCode(ARPOperationCode.ARP_REQUEST)
                .setSenderHardwareAddress(StaticField.CURRENT_MAC_ADDRESS)
                .setSenderProtocolAddress(StaticField.CURRENT_INET4_ADDRESS)
                .setTargetHardwareAddress(MacAddress.ZERO)
                .setTargetProtocolAddress(StaticField.CURRENT_GATEWAY_ADDRESS)
                .build();

        Packet ethernet = new Ethernet()
                .setDestinationMacAddress(MacAddress.BROADCAST)
                .setSourceMacAddress(StaticField.CURRENT_MAC_ADDRESS)
                .setEthernetType(ProtocolType.ARP)
                .setPacket(arp)
                .build();

        ByteBuffer buffer = FormatUtils.toDirectBuffer(ethernet.toBytes());
        PcapPktHdr pktHdr = new PcapPktHdr();
        byte[] bytes;
        for (int i=0; i<100; i++) {
            if (Jxnet.PcapSendPacket(StaticField.ARP_HANDLER, buffer, buffer.capacity()) != 0) {
                return null;
            }
            Map<Class, Packet> packets = PacketHelper.next(StaticField.ARP_HANDLER, pktHdr);
            if (packets == null) continue;
            ARP arpCap = (ARP) packets.get(ARP.class);
            if (arpCap == null) continue;
            if (arpCap.getOperationCode() == ARPOperationCode.ARP_REPLY &&
                    arpCap.getSenderProtocolAddress().equals(StaticField.CURRENT_GATEWAY_ADDRESS)) {
                return arpCap.getSenderHardwareAddress();
            }
        }
        return null;
    }

}
