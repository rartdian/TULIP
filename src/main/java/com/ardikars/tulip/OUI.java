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
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.stream.Stream;

public class OUI {

    public static String searchVendor(String MacAddr) {
        if (MacAddr == null) return "";
        MacAddr = MacAddr.trim().substring(0, 8).toUpperCase();
        final String vendorId = MacAddr;
        String res = null;    
        try (Stream<String> lines = Files.lines(new File("oui.txt").toPath(), Charset.defaultCharset())) {
            try {
                res = lines.filter(l -> l.startsWith(vendorId))
                    .findFirst().orElse("");
            } catch (Exception e) {
                return "";
            }
        } catch (IOException ex) {
            return "";
        }
        if (res == null) return "";
        String[] vendorName = res.split("#");
        if (vendorName == null) return "";
        return (vendorName[vendorName.length-1] == null) ? "" : vendorName[vendorName.length-1].trim();
    }

}
