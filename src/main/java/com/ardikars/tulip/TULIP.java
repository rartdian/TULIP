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
import dorkbox.notify.Notify;
import dorkbox.notify.Pos;
import dorkbox.util.ActionHandler;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;

public class TULIP {

    private static IDS ids;

    private static boolean isGUI = false;

    public static void main(String[] args) {
	if (args.length > 0) {
		if (args[0].equals("IPS")) {
			System.out.println("IPS AKTIF.");
			StaticField.IPS = true;
		}
	}
        gui(args);
    }

    @SuppressWarnings("unchecked")
    private static void gui(String[] args) {

	isGUI = true;

        JButton button = new JButton("Mulai");
        JTextArea textArea = new JTextArea();
        JScrollPane scrollPane = new JScrollPane(textArea);
        JComboBox comboBox = new JComboBox(getSources());

        StaticField.LOGGER = message -> {
            textArea.append(message +" \n");
            Notify.create()
                    .title("Terdeteksi.")
                    .text(message + "\n")
                    .hideAfter(1000)
                    .position(Pos.BOTTOM_RIGHT)
                    .darkStyle()
                    //.shake(100, 5)
                    .onAction(new ActionHandler<Notify>() {
                        @Override
                        public void handle(Notify value) {
                            System.out.printf("clicked.");
                        }
                    }).show();
        };


        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                String[] source = new String[1];
                try {
                    source[0] = comboBox.getSelectedItem().toString();
                } catch (Exception e) {

                }
                if (button.getText().equals("Mulai")) {
                    console(source);
                    button.setText("Berhenti");
                } else {
                    synchronized (ids) {
                        ids.stopThread();
                        button.setText("Mulai");
                    }
                }
            }
        });

        JFrame frame = new JFrame("TULIP");
        frame.setSize(500,200);
        //frame.setResizable(false);
        frame.setLayout(new BorderLayout());
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.add(comboBox, BorderLayout.NORTH);
        frame.add(button, BorderLayout.SOUTH);
        frame.add(scrollPane, BorderLayout.CENTER);

        String source = null;

        try {
            source = comboBox.getSelectedItem().toString();
        } catch (Exception ex) {
            System.err.println(ex);
        }
	frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static void console(String[] args) {

	if (!isGUI) {
        StaticField.LOGGER = message -> {
            System.out.println(message);
       	};
	}

        String source = null;

        if (args.length > 0) {
            if (args[0] != null) {
                source = args[0];
            }
        }

        try {
            StaticField.initialize(source, 1500, 1, 1, (int) StaticField.LOOP_TIME, 1);
            ids = IDS.newThread();
            ids.start();
            Runtime.getRuntime().addShutdownHook(new Thread() {
                public void run() {
                    synchronized (ids) {
                        ids.stopThread();
                    }
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private static Object[] getSources() {
        StringBuilder errbuf = new StringBuilder();
        java.util.List<PcapIf> pcapIfs = new ArrayList<PcapIf>();
        if (Jxnet.PcapFindAllDevs(pcapIfs, errbuf) != 0) {
            System.err.println(errbuf.toString());
            System.exit(0);
        }
        java.util.List<String> sources = new ArrayList<String>();
        for (PcapIf pcapIf : pcapIfs) {
            boolean ipv4 = false;
            for (PcapAddr addr : pcapIf.getAddresses()) {
                if (addr.getAddr().getSaFamily() == SockAddr.Family.AF_INET &&
                        !Inet4Address.valueOf(addr.getAddr().getData()).equals(Inet4Address.LOCALHOST) &&
			!Inet4Address.valueOf(addr.getAddr().getData()).equals(Inet4Address.ZERO)) {
                    ipv4 = true;
                }
            }
            if (ipv4)
                sources.add(pcapIf.getName());
        }
        return sources.toArray();
    }

}
