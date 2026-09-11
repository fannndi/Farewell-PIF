package dev.farewell.pif.app;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/** Keybox module: XML parsing/validation and installation into the config channel. */
final class Keyboxes {
    /**
     * Google's CURRENT hardware attestation roots (android.googleapis.com/attestation/root),
     * pinned offline. A chain that terminates anywhere else is locally valid but rejected
     * server-side; see tools/keybox_check.py and docs/DETECTION.md.
     */
    private static final Map<String, String> CURRENT_ROOTS = new HashMap<String, String>();

    static {
        CURRENT_ROOTS.put("cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
                "RSA-4096 (2022)");
        CURRENT_ROOTS.put("6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0",
                "ECDSA P-384 CA1 (2025)");
    }

    private Keyboxes() {
    }

    static JSONObject inspect(String base64Xml) {
        JSONObject result = new JSONObject();
        try {
            if (base64Xml == null || base64Xml.isEmpty()) {
                result.put("valid", false);
                result.put("error", "empty");
                return result;
            }
            byte[] xml = Base64.decode(base64Xml, Base64.DEFAULT);
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(false);
            try {
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            } catch (Throwable ignored) {
            }
            try {
                factory.setFeature("http://xml.org/sax/features/external-general-entities",
                        false);
            } catch (Throwable ignored) {
            }
            Document document = factory.newDocumentBuilder()
                    .parse(new ByteArrayInputStream(xml));
            NodeList certs = document.getElementsByTagName("Certificate");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> chain = new ArrayList<X509Certificate>();
            for (int i = 0; i < certs.getLength() && chain.size() < 8; i++) {
                try {
                    chain.add((X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(
                                    certs.item(i).getTextContent()
                                            .getBytes(StandardCharsets.UTF_8))));
                } catch (Throwable ignored) {
                }
            }
            if (chain.isEmpty()) {
                result.put("valid", false);
                result.put("error", "no certificates");
                return result;
            }
            result.put("serial", chain.get(0).getSerialNumber().toString(16));
            result.put("subject", chain.get(0).getSubjectX500Principal().getName());
            if (chain.size() < 2) {
                result.put("valid", false);
                result.put("error", "chain has one certificate");
                return result;
            }
            chain.get(0).checkValidity();
            chain.get(0).verify(chain.get(1).getPublicKey());
            result.put("valid", true);
            result.put("error", "");

            X509Certificate root = chain.get(chain.size() - 1);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(root.getEncoded());
            StringBuilder hex = new StringBuilder();
            for (byte value : hash) hex.append(String.format("%02x", value));
            String rootFp = hex.toString();
            String rootName = CURRENT_ROOTS.get(rootFp);
            result.put("rootFp", rootFp);
            result.put("anchored", rootName != null);
            result.put("rootName", rootName != null ? rootName
                    : "retired/unknown root - STRONG cannot pass");
        } catch (Throwable t) {
            try {
                result.put("valid", false);
                result.put("error", String.valueOf(t.getMessage()));
            } catch (Throwable ignored) {
            }
        }
        return result;
    }

    /** True when this SHA-256 fingerprint is one of Google's current attestation roots. */
    static boolean isCurrentRoot(String fingerprint) {
        return fingerprint != null && CURRENT_ROOTS.containsKey(fingerprint);
    }

    /** Validates and prepends a keybox to the config channel; returns its serial. */
    static String importKeybox(MainActivity activity, String base64Xml) throws Exception {
        if (base64Xml == null || base64Xml.isEmpty()) {
            throw new IllegalArgumentException("empty");
        }
        JSONObject info = inspect(base64Xml);
        if (!info.optBoolean("valid", false)) {
            throw new IllegalArgumentException(info.optString("error", "invalid"));
        }
        JSONObject config = activity.readConfig();
        JSONArray keyboxes = config.optJSONArray("kb");
        if (keyboxes == null) keyboxes = new JSONArray();
        JSONArray updated = new JSONArray();
        updated.put(base64Xml);
        for (int i = 0; i < keyboxes.length() && i < 3; i++) {
            updated.put(keyboxes.optString(i, ""));
        }
        config.put("kb", dedupe(updated));
        activity.writeConfig(config);
        return info.optString("serial", "");
    }

    static JSONObject validate(Context context) {
        try {
            JSONObject config = HookStore.readConfig(context);
            JSONArray list = config.optJSONArray("kb");
            JSONArray results = new JSONArray();
            if (list != null) {
                for (int i = 0; i < list.length(); i++) {
                    JSONObject info = inspect(list.optString(i, ""));
                    info.put("index", i);
                    results.put(info);
                }
            }
            JSONObject out = new JSONObject();
            out.put("ok", true);
            out.put("keyboxes", results);
            return out;
        } catch (Throwable t) {
            try {
                return new JSONObject().put("ok", false)
                        .put("error", String.valueOf(t.getMessage()));
            } catch (Throwable ignored) {
                return new JSONObject();
            }
        }
    }

    static JSONArray dedupe(JSONArray array) throws Exception {
        JSONArray out = new JSONArray();
        List<String> seen = new ArrayList<String>();
        for (int i = 0; i < array.length(); i++) {
            String value = array.optString(i, "");
            if (value.isEmpty() || seen.contains(value)) continue;
            seen.add(value);
            out.put(value);
        }
        return out;
    }
}
