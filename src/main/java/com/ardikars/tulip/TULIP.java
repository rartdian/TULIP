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

public class TULIP {

    private static IDS ids = IDS.newThread();
    private static ARPPing arpping = ARPPing.newThread();

    public static void main(String[] args) {

            console(args);

    }

    private static void console(String[] args) {
        String source = null;

        if (args.length > 0) {
            if (args[0] != null) {
                source = args[0];
            }
        }

        try {
            StaticField.initialize(source, 1500, 1, 1, (int) StaticField.LOOP_TIME, 1);
            //arpping.start();
            ids.start();
            Runtime.getRuntime().addShutdownHook(new Thread() {
                public void run() {
                    try {
                        Thread.sleep(StaticField.LOOP_TIME);
                        //arpping.stopThread();
                        ids.stopThread();
                        System.out.println("Closed.");
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
