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

import com.ardikars.jxnet.DataLinkType;
import com.ardikars.jxnet.Jxnet;
import com.ardikars.jxnet.MacAddress;
import com.ardikars.jxnet.packet.Packet;
import com.ardikars.jxnet.packet.arp.ARP;
import com.ardikars.jxnet.packet.arp.ARPOperationCode;
import com.ardikars.jxnet.packet.ethernet.Ethernet;
import com.ardikars.jxnet.packet.ethernet.ProtocolType;
import com.ardikars.jxnet.util.FormatUtils;

import java.nio.ByteBuffer;

public class ARPPing extends Thread {

    private MacAddress dha;

    private ARPPing(MacAddress dha) {
        this.dha = dha;
    }

    public static ARPPing newThread(MacAddress dha) {
        return new ARPPing(dha);
    }

    @Override
    public void run() {

        Packet arp = new ARP()
                .setHardwareType(DataLinkType.EN10MB)
                .setProtocolType(ProtocolType.IPV4)
                .setHardwareAddressLength((byte) 6)
                .setProtocolAddressLength((byte) 4)
                .setOperationCode(ARPOperationCode.ARP_REQUEST)
                .setSenderHardwareAddress(StaticField.CURRENT_MAC_ADDRESS)
                .setSenderProtocolAddress(StaticField.CURRENT_INET4_ADDRESS)
                .setTargetHardwareAddress(dha)
                .setTargetProtocolAddress(StaticField.CURRENT_GATEWAY_ADDRESS)
                .build();

        Packet ethernet = new Ethernet()
                .setDestinationMacAddress(dha)
                .setSourceMacAddress(StaticField.CURRENT_MAC_ADDRESS)
                .setEthernetType(ProtocolType.ARP)
                .setPacket(arp)
                .build();

        ByteBuffer buffer = FormatUtils.toDirectBuffer(ethernet.toBytes());
        if (Jxnet.PcapSendPacket(StaticField.ARP_PING_HANDLER, buffer, buffer.capacity()) != 0) {
            return;
        }

    }
}
