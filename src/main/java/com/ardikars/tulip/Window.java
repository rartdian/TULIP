package com.ardikars.tulip;

import com.ardikars.jxnet.Inet4Address;
import com.ardikars.jxnet.Jxnet;
import static com.ardikars.jxnet.Jxnet.PcapClose;
import com.ardikars.jxnet.PcapAddr;
import com.ardikars.jxnet.PcapIf;
import com.ardikars.jxnet.SockAddr;
import com.ardikars.jxnet.util.Platforms;
import dorkbox.notify.Notify;
import dorkbox.notify.Pos;
import dorkbox.util.ActionHandler;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;

public class Window extends javax.swing.JFrame {
    
    private final int counter = 20;
    
    private static IDS ids;

    private static Notify notify;
    
    public Window() {
        initComponents();
        setLocationRelativeTo(null);
        List<PcapIf> pcapIfs = new ArrayList<PcapIf>();
        if (Jxnet.PcapFindAllDevs(pcapIfs, StaticField.ERRBUF) != 0) {
            StaticField.showMessage(StaticField.ERRBUF.toString());
        }
        for (PcapIf pcapIf : pcapIfs) {
            for (PcapAddr addr : pcapIf.getAddresses()) {
                if (addr.getAddr().getSaFamily() == SockAddr.Family.AF_INET &&
                        !Inet4Address.valueOf(addr.getAddr().getData()).equals(Inet4Address.LOCALHOST) &&
			!Inet4Address.valueOf(addr.getAddr().getData()).equals(Inet4Address.ZERO)) {
                    cb_kartu_jaringan.addItem(pcapIf.getName());
                }
            }
        }
        
        StaticField.LOGGER = (message1, message2) -> {
            log.append(message1 + "\n" + message2 + "\n");
            if (StaticField.COUNTER == 20) {
                notify = Notify.create()
                        .title("Peringatan Keamanan Jaringan.")
                        .text(message1 + "\n")
                        .hideAfter(StaticField.TIMEOUT * 5)
                        .position(Pos.BOTTOM_RIGHT)
                        .onAction((Notify value) -> { });
                notify.showWarning();
                
                StaticField.COUNTER = 0;
            } else {
                StaticField.COUNTER++;
            }
        };
        
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                formWindowClosing(null);
            }
        });
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        cb_kartu_jaringan = new javax.swing.JComboBox<>();
        lbl_kartu_jaringan = new javax.swing.JLabel();
        sp_log = new javax.swing.JScrollPane();
        log = new javax.swing.JTextArea();
        btn_mulai_berhenti = new javax.swing.JButton();
        lbl_nama_app = new javax.swing.JLabel();
        sp_arp_cache = new javax.swing.JScrollPane();
        arp_cache = new javax.swing.JTextArea();
        filler_horizontal = new javax.swing.Box.Filler(new java.awt.Dimension(5, 0), new java.awt.Dimension(5, 0), new java.awt.Dimension(5, 32767));
        filler_vertical = new javax.swing.Box.Filler(new java.awt.Dimension(0, 2), new java.awt.Dimension(0, 2), new java.awt.Dimension(32767, 2));
        lbl_arp_cahce = new javax.swing.JLabel();
        lbl_catatan = new javax.swing.JLabel();
        btn_arp_cache = new javax.swing.JButton();
        MenuBar = new javax.swing.JMenuBar();
        Tentang = new javax.swing.JMenu();
        Bantuan = new javax.swing.JMenuItem();
        Aplikasi = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                formWindowClosing(evt);
            }
        });

        lbl_kartu_jaringan.setText("Nama Kartu Jaringan");

        log.setColumns(20);
        log.setRows(5);
        sp_log.setViewportView(log);

        btn_mulai_berhenti.setText("Mulai Deteksi");
        btn_mulai_berhenti.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_mulai_berhentiActionPerformed(evt);
            }
        });

        lbl_nama_app.setFont(new java.awt.Font("Dialog", 1, 24)); // NOI18N
        lbl_nama_app.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        lbl_nama_app.setText("Deteksi Serangan Pada ARP");

        arp_cache.setColumns(20);
        arp_cache.setRows(5);
        sp_arp_cache.setViewportView(arp_cache);

        filler_horizontal.setBackground(new java.awt.Color(51, 51, 51));
        filler_horizontal.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        filler_vertical.setBackground(new java.awt.Color(102, 102, 102));
        filler_vertical.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        lbl_arp_cahce.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        lbl_arp_cahce.setText("ARP Cache");

        lbl_catatan.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        lbl_catatan.setText("Catatan");

        btn_arp_cache.setText("ARP Cache");
        btn_arp_cache.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_arp_cacheActionPerformed(evt);
            }
        });

        Tentang.setText("Tentang");

        Bantuan.setText("Bantuan");
        Bantuan.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                BantuanActionPerformed(evt);
            }
        });
        Tentang.add(Bantuan);

        Aplikasi.setText("Aplikasi");
        Aplikasi.setToolTipText("");
        Aplikasi.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AplikasiActionPerformed(evt);
            }
        });
        Tentang.add(Aplikasi);

        MenuBar.add(Tentang);

        setJMenuBar(MenuBar);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(filler_horizontal, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(lbl_nama_app, javax.swing.GroupLayout.DEFAULT_SIZE, 866, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(lbl_kartu_jaringan)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(cb_kartu_jaringan, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                .addComponent(lbl_catatan, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(sp_log, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(btn_mulai_berhenti, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(12, 12, 12)
                        .addComponent(filler_vertical, javax.swing.GroupLayout.PREFERRED_SIZE, 2, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(btn_arp_cache, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(sp_arp_cache, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 369, Short.MAX_VALUE)
                            .addComponent(lbl_arp_cahce, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(lbl_nama_app, javax.swing.GroupLayout.PREFERRED_SIZE, 78, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(cb_kartu_jaringan, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(lbl_kartu_jaringan))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(filler_horizontal, javax.swing.GroupLayout.PREFERRED_SIZE, 2, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(lbl_arp_cahce, javax.swing.GroupLayout.PREFERRED_SIZE, 27, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(sp_arp_cache, javax.swing.GroupLayout.DEFAULT_SIZE, 157, Short.MAX_VALUE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(lbl_catatan, javax.swing.GroupLayout.PREFERRED_SIZE, 27, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(sp_log)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(btn_mulai_berhenti)
                            .addComponent(btn_arp_cache, javax.swing.GroupLayout.Alignment.TRAILING)))
                    .addComponent(filler_vertical, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btn_arp_cacheActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_arp_cacheActionPerformed
        try {
            arp_cache.setText("");
            Process process = null;
            BufferedReader stdIn = null;
            String str = null;
            if (Platforms.isLinux()) {
                process = Runtime.getRuntime().exec("arp -e");
            } else {
                process = Runtime.getRuntime().exec("arp -a");
            }
            stdIn = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line = "";
            while ((line = stdIn.readLine()) != null) {
                arp_cache.append(line + "\n");
            }
        } catch (IOException ex) {
            Logger.getLogger(Window.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_btn_arp_cacheActionPerformed

    private void btn_mulai_berhentiActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_mulai_berhentiActionPerformed
        StaticField.COUNTER = counter;
        if (btn_mulai_berhenti.getText().equals("Mulai Deteksi")) {
            try {
                StaticField.initialize(cb_kartu_jaringan.getSelectedItem().toString(), 1500, 1, 1, 2000, 1);
                ids = IDS.newThread();
                ids.start();
            } catch (Exception ex) {
                Logger.getLogger(Window.class.getName()).log(Level.SEVERE, null, ex);
            }
            btn_mulai_berhenti.setText("Berhenti");
        } else {
            if (ids != null) {
                synchronized (ids) {
                    ids.stopThread();
                    btn_mulai_berhenti.setText("Mulai Deteksi");
                }
            }
        }
    }//GEN-LAST:event_btn_mulai_berhentiActionPerformed

    private void formWindowClosing(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowClosing
        try {
            Thread.sleep(StaticField.TIMEOUT / 2);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if (ids != null) {
            synchronized (ids) {
                if (ids.isAlive()) {
                    ids.stopThread();
                }
            }
        }
        if (StaticField.ARP_HANDLER == null ||
                StaticField.ARP_PING_HANDLER == null ||
                StaticField.TCP_HANDLER == null) {
            return;
        }
        if (!StaticField.ARP_HANDLER.isClosed()) {
            PcapClose(StaticField.ARP_HANDLER);
        }
        if (!StaticField.TCP_HANDLER.isClosed()) {
            PcapClose(StaticField.TCP_HANDLER);
        }
        if (!StaticField.ARP_PING_HANDLER.isClosed()) {
            PcapClose(StaticField.ARP_PING_HANDLER);
        }
    }//GEN-LAST:event_formWindowClosing

    private void BantuanActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_BantuanActionPerformed
        JOptionPane.showOptionDialog(
                               null                    
                             , "\n\n" +
                                     "Untuk memulai deteksi pilih nama kartu jaringan kemudian klik \"Mulai Deteksi.\"\n" +
                                     "Sedangkan ARP Cache dapat dilihat dengan meng-klik tombol \"ARP Cache.\"" +
                                     "\n\n\n"
                             , "Bantuan"            
                             , JOptionPane.YES_NO_OPTION  
                             , JOptionPane.PLAIN_MESSAGE 
                             , null                    
                             , new String[]{"Close"}
                             , "None of your business"  
                           );
    }//GEN-LAST:event_BantuanActionPerformed

    private void AplikasiActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AplikasiActionPerformed
        JOptionPane.showOptionDialog(
                               null                    
                             , "\n\n" +
                                     "Versi 0.0.1\n" +
                                     "2017" +
                                     "\n\n"
                             , "Bantuan"            
                             , JOptionPane.YES_NO_OPTION  
                             , JOptionPane.PLAIN_MESSAGE 
                             , null                    
                             , new String[]{"Close"}
                             , "None of your business"  
                           );
    }//GEN-LAST:event_AplikasiActionPerformed

    public static void main(String args[]) {
        new Window().setVisible(true);
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenuItem Aplikasi;
    private javax.swing.JMenuItem Bantuan;
    private javax.swing.JMenuBar MenuBar;
    private javax.swing.JMenu Tentang;
    private javax.swing.JTextArea arp_cache;
    private javax.swing.JButton btn_arp_cache;
    private javax.swing.JButton btn_mulai_berhenti;
    private javax.swing.JComboBox<String> cb_kartu_jaringan;
    private javax.swing.Box.Filler filler_horizontal;
    private javax.swing.Box.Filler filler_vertical;
    private javax.swing.JLabel lbl_arp_cahce;
    private javax.swing.JLabel lbl_catatan;
    private javax.swing.JLabel lbl_kartu_jaringan;
    private javax.swing.JLabel lbl_nama_app;
    private javax.swing.JTextArea log;
    private javax.swing.JScrollPane sp_arp_cache;
    private javax.swing.JScrollPane sp_log;
    // End of variables declaration//GEN-END:variables
}
