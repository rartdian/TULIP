
import com.ardikars.jxnet.*;
import dorkbox.notify.Notify;
import dorkbox.notify.Pos;
import dorkbox.systemTray.*;
import dorkbox.util.ActionHandler;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;

class TestUnit {

	public static final URL BLUE_CAMPING = TestUnit.class.getResource("accommodation_camping.glow.0092DA.32.png");
	public static final URL BLACK_FIRE = TestUnit.class.getResource("amenity_firestation.p.000000.32.png");

	public static final URL BLACK_MAIL = TestUnit.class.getResource("amenity_post_box.p.000000.32.png");
	public static final URL GREEN_MAIL = TestUnit.class.getResource("amenity_post_box.p.39AC39.32.png");

	public static final URL BLACK_BUS = TestUnit.class.getResource("transport_bus_station.p.000000.32.png");
	public static final URL LT_GRAY_BUS = TestUnit.class.getResource("transport_bus_station.p.999999.32.png");

	public static final URL BLACK_TRAIN = TestUnit.class.getResource("transport_train_station.p.000000.32.png");
	public static final URL GREEN_TRAIN = TestUnit.class.getResource("transport_train_station.p.39AC39.32.png");
	public static final URL LT_GRAY_TRAIN = TestUnit.class.getResource("transport_train_station.p.666666.32.png");


	public static
	void main(String[] args) {
		// make sure JNA jar is on the classpath!
		new TestUnit();
	}

	private SystemTray systemTray;
	private ActionListener callbackGray;

	public	TestUnit() {
//        SwingUtil.setLookAndFeel(null);
//        SystemTray.SWING_UI = new CustomSwingUI();

		this.systemTray = SystemTray.get();
		if (systemTray == null) {
			throw new RuntimeException("Unable to load SystemTray!");
		}

		systemTray.setTooltip("Mail Checker");
		systemTray.setImage(LT_GRAY_TRAIN);
		systemTray.setStatus("No Mail");

		callbackGray = new ActionListener() {
			@Override
			public
			void actionPerformed(final ActionEvent e) {
				final MenuItem entry = (MenuItem) e.getSource();
				systemTray.setStatus(null);
				systemTray.setImage(BLACK_TRAIN);

				entry.setCallback(null);
//                systemTray.setStatus("Mail Empty");
				systemTray.getMenu().remove(entry);
				System.err.println("POW");
			}
		};


		Menu mainMenu = systemTray.getMenu();

		MenuItem greenEntry = new MenuItem("Green Mail", new ActionListener() {
			@Override
			public
			void actionPerformed(final ActionEvent e) {
				final MenuItem entry = (MenuItem) e.getSource();
				systemTray.setStatus("Some Mail!");
				systemTray.setImage(GREEN_TRAIN);

				entry.setCallback(callbackGray);
				entry.setImage(BLACK_MAIL);
				entry.setText("Delete Mail");
//                systemTray.remove(menuEntry);
			}
		});
		greenEntry.setImage(GREEN_MAIL);
		// case does not matter
		greenEntry.setShortcut('G');
		mainMenu.add(greenEntry);


		Checkbox checkbox = new Checkbox("Euro € Mail", new ActionListener() {
			@Override
			public
			void actionPerformed(final ActionEvent e) {
				System.err.println("Am i checked? " + ((Checkbox) e.getSource()).getChecked());
			}
		});
		checkbox.setShortcut('€');
		mainMenu.add(checkbox);

		mainMenu.add(new Separator());


		Menu submenu = new Menu("Options", BLUE_CAMPING);
		submenu.setShortcut('t');
		mainMenu.add(submenu);

		MenuItem disableMenu = new MenuItem("Disable menu", BLACK_BUS, new ActionListener() {
			@Override
			public
			void actionPerformed(final ActionEvent e) {
				MenuItem source = (MenuItem) e.getSource();
				source.getParent().setEnabled(false);
			}
		});
		submenu.add(disableMenu);


		submenu.add(new MenuItem("Hide tray", LT_GRAY_BUS, new ActionListener() {
			@Override
			public
			void actionPerformed(final ActionEvent e) {
				systemTray.setEnabled(false);
			}
		}));
		submenu.add(new MenuItem("Remove menu", BLACK_FIRE, new ActionListener() {
			@Override
			public
			void actionPerformed(final ActionEvent e) {
				MenuItem source = (MenuItem) e.getSource();
				source.getParent().remove();
			}
		}));


		systemTray.getMenu().add(new MenuItem("Quit", new ActionListener() {
			@Override
			public
			void actionPerformed(final ActionEvent e) {
				systemTray.shutdown();
				//System.exit(0);  not necessary if all non-daemon threads have stopped.
			}
		})).setShortcut('q'); // case does not matter
	}
}
