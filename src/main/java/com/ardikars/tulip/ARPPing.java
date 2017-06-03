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
import com.ardikars.jxnet.util.FormatUtils;

import java.nio.ByteBuffer;

public class ARPPing extends Thread {

    private ARPPing() {

    }

    public static ARPPing newThread() {
        return new ARPPing();
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
        int i = 0;
        while (i < 10) {
	    if (StaticField.ARP_PING_HANDLER.isClosed()) {
	    	break;
	    }
            if (Jxnet.PcapSendPacket(StaticField.ARP_PING_HANDLER, buffer, buffer.capacity()) != 0) {
                return;
            }
            try {
                Thread.sleep(StaticField.LOOP_TIME);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            i++;
	    }

    }

}
