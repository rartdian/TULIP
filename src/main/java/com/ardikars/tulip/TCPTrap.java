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
import com.ardikars.jxnet.packet.ethernet.*;
import com.ardikars.jxnet.packet.ip.*;
import com.ardikars.jxnet.packet.tcp.*;
import com.ardikars.jxnet.util.FormatUtils;

import java.nio.ByteBuffer;
import java.util.Map;

public class TCPTrap extends Thread {

    private static final byte[] OPTIONS = FormatUtils.toBytes("020405b40402080affff85df0000000001030307");

    private MacAddress dha;

    private TCPTrap(MacAddress dha) {
        this.dha = dha;
    }

    public static TCPTrap newThread(MacAddress dha) {
        return new TCPTrap(dha);
    }

    @Override
    public void run() {

        if (StaticField.TCP_HANDLER == null) {
            return;
        }

	short sourcePort = (short) StaticField.random.nextInt(65535 - 1 + 1);
	Inet4Address sourceAddress = Inet4Address.valueOf(StaticField.random.nextInt());

        Packet tcp = new TCP()
                .setSourcePort(sourcePort)
                .setDestinationPort((short) 80)
                .setSequence(0)
                .setAcknowledge(0)
                .setDataOffset((byte) 40)
                .setFlags(TCPFlags.newInstance((short) 2))
                .setWindowSize((short) 29200)
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
                .setSourceAddress(sourceAddress)
                .setDestinationAddress(StaticField.ADDRESS)
                .setPacket(tcp)
                .build();
        Packet tcpTrap = new Ethernet()
                .setDestinationMacAddress(dha)
                .setSourceMacAddress(StaticField.MAC_ADDRESS)
                .setEthernetType(ProtocolType.IPV4)
                .setPacket(ipv4)
                .build();

        ByteBuffer buffer = FormatUtils.toDirectBuffer(tcpTrap.toBytes());
        Map<Class, Packet> packetMap;
        PcapPktHdr pktHdr = new PcapPktHdr();

        if (Jxnet.PcapSendPacket(StaticField.TCP_HANDLER, buffer, buffer.capacity()) != 0) {
            return;
        }

        Map<Class, Packet> packets = PacketHelper.next(StaticField.TCP_HANDLER, pktHdr);
        if (packets != null) {
            Ethernet ethernet = (Ethernet) packets.get(Ethernet.class);
            if (ethernet != null) {
                if (ethernet.getDestinationMacAddress().equals(StaticField.MAC_ADDRESS)) {
                    TCP tcpCap = (TCP) packets.get(TCP.class);
                    IPv4 ipv4Cap = (IPv4) packets.get(IPv4.class);
                    if (tcpCap != null && ipv4Cap != null) {
                        if (tcpCap.getDestinationPort() == (short) 80 && tcpCap.getSourcePort() == sourcePort
                                && ipv4Cap.getDestinationAddress().equals(StaticField.ADDRESS)
                                && ipv4Cap.getSourceAddress().equals(sourceAddress)) {
                                if (StaticField.LOGGER != null) {
                                    StaticField.LOGGER.log("Anda menggunakan jaringan yang tidak aman, "
                                    + "silahkan gunakan jaringan lain.",
                                    "Mac Address Penyerang: "
                                    + dha.toString() +", IP Routing: " + "Aktif");
                                }
                                if (StaticField.IPS) {
                                    //ARPPing.newThread().start();
                                }
                            return;
                        }
                    }
                }
            }
        }
	if (StaticField.LOGGER != null) {
                StaticField.LOGGER.log("Anda menggunakan jaringan yang tidak aman, "
                                    + "silahkan gunakan jaringan lain.",
                                    "Mac Address Penyerang: "
                                    + dha.toString() +", IP Routing: " + "Tidak aktif");
        }
        if (StaticField.IPS) {
                //ARPPing.newThread().start();
        }
    }

}
