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
import com.ardikars.jxnet.MacAddress;
import com.ardikars.jxnet.packet.PacketHandler;
import com.ardikars.jxnet.packet.PacketHelper;
import com.ardikars.jxnet.packet.arp.ARP;
import com.ardikars.jxnet.packet.arp.ARPOperationCode;
import com.ardikars.jxnet.packet.ethernet.Ethernet;
import com.ardikars.jxnet.packet.ethernet.ProtocolType;

import static com.ardikars.jxnet.Jxnet.*;

public class IDS extends Thread {

    private IDS() {
    }

    public static IDS newThread() {
        return new IDS();
    }

    @Override
    public void run() {

        PacketHandler<String> packetHandler = (arg, pktHdr, packets) -> {

            Ethernet ethernet = (Ethernet) packets.get(Ethernet.class);

            if (ethernet == null || ethernet.getEthernetType() != ProtocolType.ARP) {
                return;
            }

            ARP arp = (ARP) packets.get(ARP.class);

            if (arp == null) {
                return;
            }

            MacAddress ethDst = ethernet.getDestinationMacAddress();
            MacAddress ethSrc = ethernet.getSourceMacAddress();

            MacAddress sha = null;
            MacAddress tha = null;
            Inet4Address spa = null;
            Inet4Address tpa = null;

            sha = arp.getSenderHardwareAddress();
            tha = arp.getTargetHardwareAddress();
            spa = arp.getSenderProtocolAddress();
            tpa = arp.getTargetProtocolAddress();

            if (arp.getOperationCode() != ARPOperationCode.ARP_REPLY ||
                    !ethDst.equals(StaticField.CURRENT_MAC_ADDRESS) ||
                    tpa.equals(StaticField.CURRENT_MAC_ADDRESS) || ethSrc.equals(StaticField.CURRENT_GATEWAY_MAC_ADDRESS)) {
                return;
            }
            // Check

            if (!ethSrc.equals(sha) || !ethDst.equals(tha)) {
				TCPTrap.newThread(sha).start();
            } else {
                MacAddress shaCache = StaticField.ARP_CACHE.get(spa);
                if  (shaCache == null) {
                    StaticField.ARP_CACHE.put(spa, sha);
                } else {
                    if (!sha.equals(shaCache)) {
                        TCPTrap.newThread(sha).start();
    	            } else {
						boolean UNPADDED_ETHERNET_FRAME = false;
						boolean UNKNOWN_OUI = false;
						boolean BAD_DELTA_TIME = false;

						UNPADDED_ETHERNET_FRAME = (pktHdr.getCapLen() < 60 ? true : false);
						if (OUI.searchVendor(arp.getSenderHardwareAddress().toString()).equals("")) {
                			UNKNOWN_OUI = true;
	            		}
						Long epochTimeCache = StaticField.EPOCH_TIME.get(spa);
						if (epochTimeCache == null || epochTimeCache == 0) {
							StaticField.EPOCH_TIME.put(spa, pktHdr.getTvUsec());
						} else {
							long time = (pktHdr.getTvUsec() - epochTimeCache);
							if (time < StaticField.TIME) {
								BAD_DELTA_TIME = true;
							}
							StaticField.EPOCH_TIME.put(spa, pktHdr.getTvUsec());
						}
						if ((UNPADDED_ETHERNET_FRAME && UNKNOWN_OUI) || BAD_DELTA_TIME) {
						    TCPTrap.newThread(sha).start();
						} else {
							//System.out.println("Jozz..");
						}
					}
					StaticField.ARP_CACHE.put(spa, sha);
				}
			}

        };

        PacketHelper.loop(StaticField.ARP_HANDLER, -1, packetHandler, null);

    }

    public void stopThread() {
        if (!StaticField.ARP_HANDLER.isClosed()) {
            PcapBreakLoop(StaticField.ARP_HANDLER);
        }
        try {
            Thread.sleep(StaticField.LOOP_TIME);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if (!StaticField.ARP_HANDLER.isClosed()) {
            PcapClose(StaticField.ARP_HANDLER);
        }
        if (!StaticField.ICMP_HANDLER.isClosed()) {
            PcapClose(StaticField.ICMP_HANDLER);
        }
        if (!StaticField.ARP_PING_HANDLER.isClosed()) {
            PcapClose(StaticField.ARP_PING_HANDLER);
        }
    }

}
