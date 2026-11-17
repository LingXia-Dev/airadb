package airadb;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.Looper;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Runs on the device via app_process as the shell user; reads what `pm`
 * cannot print: labels and icons.
 *
 *   apps [all]         one app per line: package TAB system(0|1) TAB label
 *   icon <pkg> <size>  the launcher icon as PNG on stdout
 *   shot <width> <q>   raw `screencap` on stdin -> JPEG at most <width> wide
 */
public final class Helper {
    public static void main(String[] args) throws Exception {
        if (args.length >= 3 && args[0].equals("shot")) {
            shot(System.in, Integer.parseInt(args[1]), Integer.parseInt(args[2]), System.out);
            System.out.flush();
            System.exit(0);
        }
        Looper.prepareMainLooper();
        Class<?> at = Class.forName("android.app.ActivityThread");
        Object thread = at.getMethod("systemMain").invoke(null);
        Context ctx = (Context) at.getMethod("getSystemContext").invoke(thread);
        PackageManager pm = ctx.getPackageManager();
        PrintStream out = System.out;
        if (args.length >= 1 && args[0].equals("apps")) {
            boolean all = args.length >= 2 && args[1].equals("all");
            Set<String> visible = launchable(pm);
            for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
                if (!all && !visible.contains(ai.packageName)) continue;
                boolean system = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                String label = String.valueOf(pm.getApplicationLabel(ai)).replaceAll("[\\x00-\\x1f]", " ");
                out.print(ai.packageName + "\t" + (system ? 1 : 0) + "\t" + label + "\n");
            }
        } else if (args.length >= 3 && args[0].equals("icon")) {
            int size = Integer.parseInt(args[2]);
            Drawable d = pm.getApplicationIcon(args[1]);
            Bitmap bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
            d.setBounds(0, 0, size, size);
            d.draw(new Canvas(bmp));
            bmp.compress(Bitmap.CompressFormat.PNG, 100, out);
        } else {
            System.err.println("usage: apps [all] | icon <pkg> <size> | shot <width> <quality>");
            System.exit(2);
        }
        out.flush();
        System.exit(0);
    }

    /**
     * Raw screencap: width, height, format (u32 LE), plus a u32 colour
     * space on Android 9+, then the pixels. The header size follows from
     * the length. Scaled down (never up) and sent as JPEG: a fraction of
     * the full-size PNG over a slow network.
     */
    private static void shot(InputStream in, int maxWidth, int quality, PrintStream out) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(8 << 20);
        byte[] chunk = new byte[1 << 16];
        for (int n; (n = in.read(chunk)) > 0; ) buf.write(chunk, 0, n);
        byte[] raw = buf.toByteArray();
        ByteBuffer head = ByteBuffer.wrap(raw).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        int w = head.getInt(0), h = head.getInt(4), format = head.getInt(8);
        // PixelFormat: RGBA_8888 = 1, RGBX_8888 = 2, RGB_565 = 4.
        boolean rgb565 = format == 4;
        int pixels = w * h * (rgb565 ? 2 : 4);
        int header = raw.length - pixels;
        if (w <= 0 || h <= 0 || (header != 12 && header != 16)) {
            throw new IllegalStateException("unexpected screencap: " + w + "x" + h + " format " + format + ", " + raw.length + " bytes");
        }
        Bitmap bmp = Bitmap.createBitmap(w, h, rgb565 ? Bitmap.Config.RGB_565 : Bitmap.Config.ARGB_8888);
        // A direct buffer: some devices crash copying from an offset heap one.
        ByteBuffer px = ByteBuffer.allocateDirect(pixels);
        px.put(raw, header, pixels).rewind();
        raw = null;
        bmp.copyPixelsFromBuffer(px);
        if (w > maxWidth) {
            Bitmap scaled = Bitmap.createScaledBitmap(bmp, maxWidth, Math.max(1, (int) ((long) h * maxWidth / w)), true);
            bmp.recycle();
            bmp = scaled;
        }
        bmp.compress(Bitmap.CompressFormat.JPEG, quality, out);
    }

    /** Packages with a phone or TV launcher entry. */
    private static Set<String> launchable(PackageManager pm) {
        Set<String> set = new HashSet<String>();
        for (String category : new String[] {Intent.CATEGORY_LAUNCHER, "android.intent.category.LEANBACK_LAUNCHER"}) {
            List<ResolveInfo> list = pm.queryIntentActivities(new Intent(Intent.ACTION_MAIN).addCategory(category), 0);
            for (ResolveInfo ri : list) set.add(ri.activityInfo.packageName);
        }
        return set;
    }
}
