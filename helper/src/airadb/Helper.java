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

import java.io.PrintStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Runs on the device via app_process as the shell user; reads what `pm`
 * cannot print: labels and icons.
 *
 *   apps [all]         one app per line: package TAB system(0|1) TAB label
 *   icon <pkg> <size>  the launcher icon as PNG on stdout
 */
public final class Helper {
    public static void main(String[] args) throws Exception {
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
            System.err.println("usage: apps [all] | icon <pkg> <size>");
            System.exit(2);
        }
        out.flush();
        System.exit(0);
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
