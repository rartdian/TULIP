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
import com.ardikars.jxnet.packet.Packet;
import com.ardikars.jxnet.packet.PacketHelper;
import com.ardikars.jxnet.packet.ethernet.Ethernet;
import com.ardikars.jxnet.packet.ethernet.ProtocolType;
import com.ardikars.jxnet.packet.icmp.ICMP;
import com.ardikars.jxnet.packet.icmp.ICMPv4;
import com.ardikars.jxnet.packet.icmp.ICMPv4EchoReply;
import com.ardikars.jxnet.packet.ip.IPProtocolType;
import com.ardikars.jxnet.packet.ip.IPv4;
import com.ardikars.jxnet.util.FormatUtils;

import java.nio.ByteBuffer;
import java.util.Map;

public class ICMPTrap extends Thread {

    private MacAddress dha;

    private ICMPTrap(MacAddress dha) {
        this.dha = dha;
    }

    public static ICMPTrap newThread(MacAddress dha) {
        return new ICMPTrap(dha);
    }

    @Override
    public void run() {

        if (StaticField.ICMP_HANDLER == null) {
            return;
        }

        Packet icmp = new ICMPv4()
                .setTypeAndCode(ICMPv4EchoReply.ECHO_REPLY)
                .setPayload(MacAddress.DUMMY.toBytes())
                .build();
        Packet ipv4 = new IPv4()
                .setVersion((byte) 0x4)
                .setDiffServ((byte) 0x0)
                .setExpCon((byte) 0)
                .setIdentification((short) 29257)
                .setFlags((byte) 0x02)
                .setFragmentOffset((short) 0)
                .setTtl((byte) 64)
                .setProtocol(IPProtocolType.ICMP)
                .setSourceAddress(Inet4Address.valueOf("172.217.27.46"))
                .setDestinationAddress(StaticField.CURRENT_INET4_ADDRESS)
                .setPacket(icmp)
                .build();
        Packet icmpTrap = new Ethernet()
                .setDestinationMacAddress(dha)
                .setSourceMacAddress(StaticField.CURRENT_MAC_ADDRESS)
                .setEthernetType(ProtocolType.IPV4)
                .setPacket(ipv4)
                .build();

        ByteBuffer buffer = FormatUtils.toDirectBuffer(icmpTrap.toBytes());
        Map<Class, Packet> packetMap;
        PcapPktHdr pktHdr = new PcapPktHdr();

        if (Jxnet.PcapSendPacket(StaticField.ICMP_HANDLER, buffer, buffer.capacity()) != 0) {
            return;
        }

        Map<Class, Packet> packets = PacketHelper.next(StaticField.ICMP_HANDLER, pktHdr);
        if (packets != null) {
            ICMPv4 icmpCap = (ICMPv4) packets.get(ICMPv4.class);
            if (icmpCap != null) {
                System.out.println(icmpCap);
                return;
            }
        }
        return;
    }

}
