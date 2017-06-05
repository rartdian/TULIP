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
import com.ardikars.jxnet.packet.*;
import com.ardikars.jxnet.packet.arp.*;
import com.ardikars.jxnet.packet.ethernet.*;
import com.ardikars.jxnet.util.*;
import java.io.IOException;

import java.nio.ByteBuffer;
import java.util.*;
import javax.swing.JOptionPane;

public class StaticField {

    public static boolean IPS = false;

    public static boolean isGUI = false;

    public static Logger LOGGER;

    public static StringBuilder ERRBUF = new StringBuilder();
    
    public static int COUNTER;
    
    public static String SOURCE;
    public static int SNAPLEN = 1500;
    public static int PROMISC = 1;
    public static int IMMEDIATE = 1;
    public static int TIMEOUT = 2000;
    public static int OPTIMIZE = 1;

    public static volatile Pcap ARP_HANDLER;
    public static volatile Pcap TCP_HANDLER;
    public static volatile Pcap ARP_PING_HANDLER;

    
    public static Inet4Address ADDRESS = Inet4Address.valueOf(0);
    public static Inet4Address NETMASK_ADDRESS = Inet4Address.valueOf(0);
    public static Inet4Address NETWORK_ADDRESS = Inet4Address.valueOf(0);
    public static Inet4Address BROADCAST_ADDRESS = Inet4Address.valueOf(0);
    public static Inet4Address DESTINATION_ADDRESS = Inet4Address.valueOf(0);
    public static MacAddress MAC_ADDRESS = MacAddress.valueOf(0);
    
    public static Inet4Address GATEWAY_ADDRESS = Inet4Address.valueOf(0);
    public static MacAddress GATEWAY_MAC_ADDRESS = MacAddress.valueOf(0);
    
    
    public static Map<Inet4Address, MacAddress> ARP_CACHE = new HashMap<Inet4Address, MacAddress>();
    public static Map<Inet4Address, Long> EPOCH_TIME = new HashMap<Inet4Address, Long>();

    //public static long LOOP_TIME = 2000;

    public static long TIME = 100000;

    public static Random random = new Random();

    public static void initialize(String src, int snaplen, int promisc, int immediate, int to_ms, int optimize) throws Exception {

        Preconditions.CheckArgument(snaplen >= 1500 || snaplen <= 65535);
        Preconditions.CheckArgument(promisc == 1 || promisc == 0);
        Preconditions.CheckArgument(immediate == 1 || immediate == 0);
        Preconditions.CheckArgument(to_ms > 0);
        Preconditions.CheckArgument(optimize == 1 || optimize == 0);

        StringBuilder errbuf = new StringBuilder();

        if (src == null) {
            SOURCE = LookupNetworkInterface(ADDRESS, NETMASK_ADDRESS, NETWORK_ADDRESS, BROADCAST_ADDRESS, DESTINATION_ADDRESS, MAC_ADDRESS, errbuf);
        } else {
            SOURCE = LookupNetworkInterface(src, ADDRESS, NETMASK_ADDRESS, NETWORK_ADDRESS, BROADCAST_ADDRESS, DESTINATION_ADDRESS, MAC_ADDRESS, errbuf);
        }
        if (SOURCE == null) {
            showMessage("Perikasa koneksi jaringan LAN anda.");
            return;
        }
        SNAPLEN = snaplen;
        PROMISC = promisc;
        IMMEDIATE = immediate;
        TIMEOUT = to_ms;
        OPTIMIZE = optimize;

        GATEWAY_ADDRESS = AddrUtils.GetGatewayAddress();
        if (GATEWAY_ADDRESS == null) {
            showMessage("Perikasa koneksi jaringan LAN anda.");
            return;
        }

	if ((ARP_HANDLER = openLive("arp")) == null) {
            showMessage(ERRBUF.toString());
            return;
        }
        if ((TCP_HANDLER = openLive("tcp")) == null) {
            showMessage(ERRBUF.toString());
            return;
        }
        if ((ARP_PING_HANDLER = openLive("arp")) == null) {
            showMessage(ERRBUF.toString());
            return;
        }

	if ((GATEWAY_MAC_ADDRESS = getGwHwAddrFromArp()) == null) {
            showMessage("Periksa koneksi jaringan LAN anda.");
        }
	
	System.out.println("Interface           : " + SOURCE);
        System.out.println("Address             : " + ADDRESS + "" +
                " (" + MAC_ADDRESS + ")");
        System.out.println("Gateway             : " + GATEWAY_ADDRESS + "" +
                " (" + GATEWAY_MAC_ADDRESS + ") ");
        System.out.println("Netmask Address     : " + NETMASK_ADDRESS);
        System.out.println("Network Address     : " + NETWORK_ADDRESS);

    }

    public static Pcap openLive(String filter) throws Exception {

        ERRBUF.setLength(0);
        
        Pcap pcap = Jxnet.PcapCreate(SOURCE, ERRBUF);

        if (pcap == null) {
            return null;
        }

        if (Jxnet.PcapSetSnaplen(pcap, SNAPLEN) != 0) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            ERRBUF.append(err);
            return null;
        }

        if (Jxnet.PcapSetPromisc(pcap, PROMISC) != 0 ) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            ERRBUF.append(err);
            return null;
        }

	if (!Platforms.isWindows()) {
            if (Jxnet.PcapSetImmediateMode(pcap, IMMEDIATE) != 0 ) {
                String err = Jxnet.PcapGetErr(pcap);
                Jxnet.PcapClose(pcap);
                ERRBUF.append(err);
                return null;
            }
	}

        if (Jxnet.PcapSetTimeout(pcap, TIMEOUT) != 0) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            ERRBUF.append(err);
            return null;
        }

        if (Jxnet.PcapActivate(pcap) != 0) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            ERRBUF.append(err);
            return null;
        }
	
	if (!Platforms.isWindows()) {
            if (Jxnet.PcapSetDirection(pcap, PcapDirection.PCAP_D_IN) != 0) {
                String err = Jxnet.PcapGetErr(pcap);
                Jxnet.PcapClose(pcap);
                ERRBUF.append(err);
                return null;
            }
	}

        BpfProgram fp = new BpfProgram();
        if (Jxnet.PcapCompile(pcap, fp, filter, OPTIMIZE,
                NETMASK_ADDRESS.toInt()) != 0 ) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            ERRBUF.append(err);
            return null;
        }

        if (Jxnet.PcapSetFilter(pcap, fp) != 0) {
            String err = Jxnet.PcapGetErr(pcap);
            Jxnet.PcapClose(pcap);
            ERRBUF.append(err);
            return null;
        }
        return pcap;
    }

    public static MacAddress getGwHwAddrFromArp() {

        Packet arp = new ARP()
                .setHardwareType(DataLinkType.EN10MB)
                .setProtocolType(ProtocolType.IPV4)
                .setHardwareAddressLength((byte) 6)
                .setProtocolAddressLength((byte) 4)
                .setOperationCode(ARPOperationCode.ARP_REQUEST)
                .setSenderHardwareAddress(MAC_ADDRESS)
                .setSenderProtocolAddress(ADDRESS)
                .setTargetHardwareAddress(MacAddress.ZERO)
                .setTargetProtocolAddress(GATEWAY_ADDRESS)
                .build();

        Packet ethernet = new Ethernet()
                .setDestinationMacAddress(MacAddress.BROADCAST)
                .setSourceMacAddress(MAC_ADDRESS)
                .setEthernetType(ProtocolType.ARP)
                .setPacket(arp)
                .build();

        ByteBuffer buffer = FormatUtils.toDirectBuffer(ethernet.toBytes());
        PcapPktHdr pktHdr = new PcapPktHdr();
        byte[] bytes;
        for (int i=0; i<50; i++) {
            if (Jxnet.PcapSendPacket(ARP_HANDLER, buffer, buffer.capacity()) != 0) {
                return null;
            }
            Map<Class, Packet> packets = PacketHelper.next(ARP_HANDLER, pktHdr);
            if (packets == null) continue;
            ARP arpCap = (ARP) packets.get(ARP.class);
            if (arpCap == null) continue;
            if (arpCap.getOperationCode() == ARPOperationCode.ARP_REPLY &&
                    arpCap.getSenderProtocolAddress().equals(GATEWAY_ADDRESS)) {
                return arpCap.getSenderHardwareAddress();
            }
	    try{Thread.sleep(StaticField.TIMEOUT);}catch(InterruptedException e){System.out.println(e);}
        }
        return null;
    }

    /**
     * Get network interface information.
     * @param address ipv4 address.
     * @param netmask netmask address.
     * @param netaddr network address.
     * @param broadaddr broadcast address.
     * @param dstaddr destination address.
     * @param macAddress mac address.
     * @param description description.
     * @return interface name.
     */
    public static String LookupNetworkInterface(Inet4Address address,
            Inet4Address netmask,
            Inet4Address netaddr,
            Inet4Address broadaddr,
            Inet4Address dstaddr,
            MacAddress macAddress,
            StringBuilder description) {

        Preconditions.CheckNotNull(address);
        Preconditions.CheckNotNull(netmask);
        Preconditions.CheckNotNull(netaddr);
        Preconditions.CheckNotNull(broadaddr);
        Preconditions.CheckNotNull(dstaddr);
        Preconditions.CheckNotNull(description);

        StringBuilder errbuf = new StringBuilder();

        List<PcapIf> ifs = new ArrayList<PcapIf>();
        if (Jxnet.PcapFindAllDevs(ifs, errbuf) != Jxnet.OK) {
            return null;
        }

        description.setLength(0);

        for (PcapIf dev : ifs) {
            for (PcapAddr addr : dev.getAddresses()) {
                if (addr.getAddr().getData() == null || addr.getBroadAddr().getData() == null ||
                        addr.getNetmask().getData() == null) {
                    continue;
                }
                if (addr.getAddr().getSaFamily() == SockAddr.Family.AF_INET &&
                        !Inet4Address.valueOf(addr.getAddr().getData()).equals(Inet4Address.ZERO) &&
                        !Inet4Address.valueOf(addr.getAddr().getData()).equals(Inet4Address.LOCALHOST) &&
                        !Inet4Address.valueOf(addr.getBroadAddr().getData()).equals(Inet4Address.ZERO) &&
                        !Inet4Address.valueOf(addr.getNetmask().getData()).equals(Inet4Address.ZERO)
                        ) {
                    address.update(Inet4Address.valueOf(addr.getAddr().getData()));
                    netmask.update(Inet4Address.valueOf(addr.getNetmask().getData()));
                    netaddr.update(Inet4Address.valueOf(address.toInt() & netmask.toInt()));
                    broadaddr.update(Inet4Address.valueOf(addr.getBroadAddr().getData()));
                    if (addr.getDstAddr().getData() != null) {
                        dstaddr.update(Inet4Address.valueOf(addr.getDstAddr().getData()));
                    } else {
                        dstaddr.update(Inet4Address.ZERO);
                    }
                    macAddress.update(MacAddress.fromNicName(dev.getName()));
                    if (dev.getDescription() != null) {
                        description.append(dev.getDescription());
                    }
                    return dev.getName();
                }
            }
        }
        return null;
    }
    
    public static String LookupNetworkInterface(String source, Inet4Address address,
            Inet4Address netmask,
            Inet4Address netaddr,
            Inet4Address broadaddr,
            Inet4Address dstaddr,
            MacAddress macAddress,
            StringBuilder description) {

        Preconditions.CheckNotNull(address);
        Preconditions.CheckNotNull(netmask);
        Preconditions.CheckNotNull(netaddr);
        Preconditions.CheckNotNull(broadaddr);
        Preconditions.CheckNotNull(dstaddr);
        Preconditions.CheckNotNull(description);

        StringBuilder errbuf = new StringBuilder();

        List<PcapIf> ifs = new ArrayList<PcapIf>();
        if (Jxnet.PcapFindAllDevs(ifs, errbuf) != Jxnet.OK) {
            return null;
        }

        description.setLength(0);

        for (PcapIf dev : ifs) {
            if (dev.getName().equals(source)) {
                for (PcapAddr addr : dev.getAddresses()) {
                    if (addr.getAddr().getData() == null || addr.getBroadAddr().getData() == null ||
                            addr.getNetmask().getData() == null) {
                        continue;
                    }
                    if (addr.getAddr().getSaFamily() == SockAddr.Family.AF_INET &&
                            !Inet4Address.valueOf(addr.getAddr().getData()).equals(Inet4Address.ZERO) &&
                            !Inet4Address.valueOf(addr.getAddr().getData()).equals(Inet4Address.LOCALHOST) &&
                            !Inet4Address.valueOf(addr.getBroadAddr().getData()).equals(Inet4Address.ZERO) &&
                            !Inet4Address.valueOf(addr.getNetmask().getData()).equals(Inet4Address.ZERO)
                            ) {
                        address.update(Inet4Address.valueOf(addr.getAddr().getData()));
                        netmask.update(Inet4Address.valueOf(addr.getNetmask().getData()));
                        netaddr.update(Inet4Address.valueOf(address.toInt() & netmask.toInt()));
                        broadaddr.update(Inet4Address.valueOf(addr.getBroadAddr().getData()));
                        if (addr.getDstAddr().getData() != null) {
                            dstaddr.update(Inet4Address.valueOf(addr.getDstAddr().getData()));
                        } else {
                            dstaddr.update(Inet4Address.ZERO);
                        }
                        macAddress.update(MacAddress.fromNicName(dev.getName()));
                        if (dev.getDescription() != null) {
                            description.append(dev.getDescription());
                        }
                        return dev.getName();
                    }
                }
            }
        }
        return null;
    }
    
    public static void showMessage(String message) {
        JOptionPane.showMessageDialog(null, message);
    }
    
}
