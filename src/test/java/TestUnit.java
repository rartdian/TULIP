
import com.ardikars.jxnet.*;
import dorkbox.notify.Notify;
import dorkbox.notify.Pos;
import dorkbox.util.ActionHandler;

class TestUnit {

	public static void main(String[] args) {
		Notify.create()
				.title("WARNIG")
				.text("jfksldfjdlskfds")
				.hideAfter(5000)
				.position(Pos.BOTTOM_RIGHT)
				.darkStyle()
				.shake(1300, 4)
				.onAction(new ActionHandler<Notify>() {
					@Override
					public void handle(Notify value) {
						System.out.printf("clicked.");
					}
				}).show();

	}

}
