package dev.farewell.pif.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import org.json.JSONObject;

/**
 * Restores the hook channel after a reboot or app update.
 *
 * Some ROMs (MIUI) drop unknown Settings.Global keys on boot, which silently disables the
 * hot-loaded hook until the controller app is opened. installHook() is idempotent, so this is a
 * cheap no-op when the settings survived, and it never restarts any process.
 */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent != null ? intent.getAction() : null;
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            return;
        }
        try {
            JSONObject config = HookStore.readConfig(context);
            if (config.optInt("en", 0) != 1) return;
            Log.i("FarewellPIF", "boot restore: " + HookStore.installHook(context));
        } catch (Throwable t) {
            Log.e("FarewellPIF", "boot restore failed", t);
        }
    }
}
