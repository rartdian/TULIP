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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Stream;

public class OUI {

    public static String searchVendor(String MacAddr) {
        MacAddr = MacAddr.trim().substring(0, 8).toUpperCase();
        final String vendorId = MacAddr;
        String res = null;
        try (Stream<String> lines = Files.lines(new File("oui.txt").toPath(), Charset.defaultCharset())) {
            res = lines.filter(l -> l.startsWith(vendorId)).findFirst().orElse(null);
        } catch (IOException ex) {
            return res;
        }
        if (res == null) return "";
        String[] vendorName = res.split("#");
        if (vendorName == null) return  "";
        return (vendorName[vendorName.length-1] == null) ? "" : vendorName[vendorName.length-1].trim();
    }

    public static void update() {
        Map<String, String> oui = new HashMap<>();
        Properties ouiProperties = null;
        FileWriter writer = null;
        System.out.println("Started");
        try {
            Stream<String> lines = Files.lines(new File("oui.txt").toPath(), Charset.defaultCharset());
            lines.forEach(item -> {
                if (item.length() > 8) {
                    if (item.charAt(2) == ':' || item.charAt(5) == '-') {
                        String str = item.replaceAll(":", "").
                                replaceAll("-", "");
                        str = str.substring(0, 6);
                        if (str != null) {
                            int key;
                            try {
                                key = Integer.parseInt(str, 16);
                                String[] vendorName = item.split("#");
                                if (vendorName[vendorName.length - 1] != null) {
                                    String value = vendorName[vendorName.length-1].trim();
                                    oui.put(String.valueOf(key), value);
                                    System.out.println(str);
                                }
                            } catch (NumberFormatException ex) {
                                // continue
                            }
                        }
                    }
                }
            });

            ouiProperties = new Properties();
            writer = new FileWriter("oui.properties");
            ouiProperties.putAll(oui);
            ouiProperties.store(writer, "OUI");
            writer.close();
        } catch (IOException ex) {
            System.err.println(ex);
        }
    }
}
