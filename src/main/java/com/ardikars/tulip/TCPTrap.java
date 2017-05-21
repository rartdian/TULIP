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

import com.ardikars.jxnet.Inet4Address;
import com.ardikars.jxnet.Jxnet;
import com.ardikars.jxnet.MacAddress;
import com.ardikars.jxnet.PcapPktHdr;
import com.ardikars.jxnet.packet.Packet;
import com.ardikars.jxnet.packet.PacketHelper;
import com.ardikars.jxnet.packet.ethernet.Ethernet;
import com.ardikars.jxnet.packet.ethernet.ProtocolType;
import com.ardikars.jxnet.packet.ip.IPProtocolType;
import com.ardikars.jxnet.packet.ip.IPv4;
import com.ardikars.jxnet.packet.tcp.TCP;
import com.ardikars.jxnet.packet.tcp.TCPFlags;
import com.ardikars.jxnet.packet.udp.UDP;
import com.ardikars.jxnet.util.FormatUtils;

import java.nio.ByteBuffer;
import java.util.Map;

public class TCPTrap extends Thread {

    private static final byte[] OPTIONS = FormatUtils.toBytes("020405840402080accffb15c000c6eef01030307");

    private MacAddress dha;

    private TCPTrap(MacAddress dha) {
        this.dha = dha;
    }

    public static TCPTrap newThread(MacAddress dha) {
        return new TCPTrap(dha);
    }

    @Override
    public void run() {

        if (StaticField.ICMP_HANDLER == null) {
            return;
        }

        Packet tcp = new TCP()
                .setSourcePort((short) 22)
                .setDestinationPort((short) 53524)
                .setSequence(0)
                .setAcknowledge(1)
                .setDataOffset((byte) 40)
                .setFlags(TCPFlags.newInstance((short) 12))
                .setWindowSize((short) 28960)
                .setUrgentPointer((short) 0)
                .setOptions(OPTIONS)
                .build();
        Packet ipv4 = new IPv4()
                .setVersion((byte) 0x4)
                .setDiffServ((byte) 0x0)
                .setExpCon((byte) 0)
                .setIdentification((short) 29257)
                .setFlags((byte) 0x02)
                .setFragmentOffset((short) 0)
                .setTtl((byte) 64)
                .setProtocol(IPProtocolType.TCP)
                .setSourceAddress(Inet4Address.valueOf("172.217.27.46"))
                .setDestinationAddress(StaticField.CURRENT_INET4_ADDRESS)
                .setPacket(tcp)
                .build();
        Packet udpTrap = new Ethernet()
                .setDestinationMacAddress(dha)
                .setSourceMacAddress(StaticField.CURRENT_MAC_ADDRESS)
                .setEthernetType(ProtocolType.IPV4)
                .setPacket(ipv4)
                .build();

        ByteBuffer buffer = FormatUtils.toDirectBuffer(udpTrap.toBytes());
        Map<Class, Packet> packetMap;
        PcapPktHdr pktHdr = new PcapPktHdr();

        if (Jxnet.PcapSendPacket(StaticField.ICMP_HANDLER, buffer, buffer.capacity()) != 0) {
            return;
        }

        Map<Class, Packet> packets = PacketHelper.next(StaticField.ICMP_HANDLER, pktHdr);
        if (packets != null) {
            TCP tcpCap = (TCP) packets.get(TCP.class);
            if (tcpCap != null) {
                System.out.println(tcpCap);
                return;
            }
        }
        return;
    }

}