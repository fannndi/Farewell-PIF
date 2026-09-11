package dev.farewell.pif.app;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Self-audit inspired by PIF Detector (docs/DETECTION.md): reports what a local detector or a
 * picky banking app could observe, and refuses keybox modes that cannot work server-side.
 *
 * Everything is offline. The interesting checks are the chain structure of the chain we actually
 * serve (links, CA flags, challenge echo, leaf signature algorithm, root anchor) plus the native
 * property hook state.
 */
final class Security {
    private Security() {
    }

    static String audit(MainActivity activity) {
        JSONObject out = new JSONObject();
        JSONArray lines = new JSONArray();
        boolean ok = true;
        try {
            JSONObject config = activity.readConfig();
            int flags = config.optInt("fl", 0);
            boolean keyboxFlag = (flags & 2) != 0;
            boolean storeMode = (flags & 64) != 0;
            boolean globalMode = (flags & 32) != 0;
            JSONObject profile = config.optJSONObject("pf");
            boolean hasProfile = profile != null
                    && profile.optString("FINGERPRINT", "").length() > 0;

            ok &= add(lines, hasProfile, "Profile: " + (hasProfile
                    ? profile.optString("MODEL", "custom") + " / "
                            + profile.optString("FINGERPRINT", "").substring(0,
                                    Math.min(48, profile.optString("FINGERPRINT", "").length()))
                    : "missing - import Pif-props.json"));
            String mode = keyboxFlag ? "Profile + Keybox" : "PIF profile only";
            if (storeMode) mode += " + Store";
            if (globalMode) mode += " + Global";
            add(lines, true, "Mode: " + mode + (keyboxFlag
                    ? "" : " (no keybox attestation; app availability paths still work)"));

            JSONArray boxes = config.optJSONArray("kb");
            JSONArray details = new JSONArray();
            boolean anyValid = false;
            boolean anyAnchored = false;
            if (boxes != null) {
                for (int i = 0; i < boxes.length(); i++) {
                    JSONObject info = Keyboxes.inspect(boxes.optString(i, ""));
                    info.put("index", i);
                    details.put(info);
                    boolean valid = info.optBoolean("valid");
                    boolean anchored = info.optBoolean("anchored");
                    anyValid |= valid;
                    anyAnchored |= anchored;
                    String text;
                    if (!valid) {
                        text = "Keybox #" + (i + 1) + ": invalid (" + info.optString("error") + ")";
                    } else if (anchored) {
                        text = "Keybox #" + (i + 1) + ": valid, anchored to "
                                + info.optString("rootName");
                    } else {
                        text = "Keybox #" + (i + 1) + ": valid locally but "
                                + info.optString("rootName", "not anchored");
                    }
                    add(lines, valid && anchored, text);
                }
            }
            out.put("keyboxes", details);
            out.put("anchored", anyAnchored);

            if (keyboxFlag && !anyAnchored) {
                ok = false;
                add(lines, false, keyboxFlag
                        ? "Keybox mode is ON without a current root: the forge is rejected"
                                + " server-side. Install a current keybox or switch to PIF profile mode."
                        : "No keybox installed");
            }

            JSONObject live = new JSONObject(Diag.invokeHookLoaded("selfTest"));
            out.put("live", live);
            boolean forged = live.optBoolean("forged");
            ok &= add(lines, forged, forged
                    ? "Live forge: hook loaded, forged chain of " + live.optInt("chainLength")
                            + " certificates"
                    : "Live forge failed: " + live.optString("hint", live.optString("error")));

            JSONObject chainAudit = live.optJSONObject("audit");
            if (chainAudit != null) {
                ok &= add(lines, chainAudit.optBoolean("linksOk"), "Chain links verify");
                ok &= add(lines, chainAudit.optBoolean("issuersCa"),
                        "Every issuer certificate is a CA");
                ok &= add(lines, chainAudit.optBoolean("challengeEchoed"),
                        "Attestation challenge is echoed");
                String sigAlg = chainAudit.optString("leafSigAlg", "?");
                boolean sigOk = !sigAlg.toUpperCase().startsWith("SHA512");
                ok &= add(lines, sigOk, "Leaf signature algorithm: " + sigAlg
                        + (sigOk ? "" : " (tracks the requested digest!)"));
                String rootFp = chainAudit.optString("rootFp", "");
                boolean rootCurrent = Keyboxes.isCurrentRoot(rootFp);
                add(lines, rootCurrent, "Served chain root: "
                        + (rootFp.isEmpty() ? "unknown"
                                : rootCurrent ? "current Google root"
                                        : "retired/unknown - STRONG will be rejected"));
                if (keyboxFlag && !rootCurrent && !rootFp.isEmpty()) ok = false;
            } else {
                add(lines, false, "Chain audit unavailable");
                ok = false;
            }

            String nativeText = Diag.systemNativeProbe();
            JSONObject nativeJson = new JSONObject(nativeText);
            if (!nativeJson.has("native")) {
                nativeJson = new JSONObject(Diag.nativeProbeTest(activity));
            }
            out.put("native", nativeJson);
            boolean nativeOk = nativeJson.has("native");
            add(lines, nativeOk, nativeOk
                    ? "Native property hook: " + nativeJson.optString("native")
                    : "Native property hook inactive: "
                            + nativeJson.optString("error", "not loaded"));
            if (!nativeOk) ok = false;

            out.put("lines", lines);
            out.put("ok", ok);
            out.put("verdict", ok ? "PASS" : "ATTENTION");
        } catch (Throwable t) {
            try {
                out.put("ok", false);
                out.put("verdict", "ERROR");
                out.put("error", String.valueOf(t));
                out.put("lines", lines);
            } catch (Throwable ignored) {
            }
        }
        return out.toString();
    }

    private static boolean add(JSONArray lines, boolean pass, String text) {
        try {
            lines.put((pass ? "PASS  " : "FAIL  ") + text);
        } catch (Throwable ignored) {
        }
        return pass;
    }
}
