package dev.farewell.pif;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Keybox XML parsing with multi-keybox support and health validation.
 *
 * A keybox is usable when
 *   - at least two certificates are present,
 *   - the first certificate is currently valid and is signed by the second,
 *   - the private key actually matches the first certificate's public key.
 */
final class Keybox {
    static final AlgorithmIdentifier EC_SIG_ALG =
            new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
    static final AlgorithmIdentifier RSA_SIG_ALG =
            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);

    private static final int MAX_BASE64 = 512 * 1024;
    private static final int MAX_XML = 384 * 1024;

    private static final Map<String, List<Entry>> CACHE = new HashMap<String, List<Entry>>();
    private static String sCacheKey;

    private Keybox() {
    }

    static final class Entry {
        final String algorithm;
        final PrivateKey privateKey;
        final X509Certificate[] chain;
        final AlgorithmIdentifier sigAlg;
        final String jcaSigAlg;

        Entry(String algorithm, PrivateKey privateKey, X509Certificate[] chain,
              AlgorithmIdentifier sigAlg, String jcaSigAlg) {
            this.algorithm = algorithm;
            this.privateKey = privateKey;
            this.chain = chain;
            this.sigAlg = sigAlg;
            this.jcaSigAlg = jcaSigAlg;
        }

        byte[] chainBytes() {
            try {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                for (X509Certificate cert : chain) out.write(cert.getEncoded());
                out.flush();
                return out.toByteArray();
            } catch (Throwable t) {
                return null;
            }
        }

        /** Null when the keybox is healthy, otherwise a human readable problem. */
        String problem() {
            try {
                if (chain == null || chain.length < 2) return "chain has fewer than 2 certificates";
                chain[0].checkValidity();
                chain[0].verify(chain[1].getPublicKey());
            } catch (java.security.cert.CertificateExpiredException e) {
                return "leaf certificate expired";
            } catch (java.security.cert.CertificateNotYetValidException e) {
                return "leaf certificate not yet valid";
            } catch (Throwable t) {
                return "chain signature invalid: " + t.getMessage();
            }
            try {
                byte[] probe = new byte[32];
                for (int i = 0; i < probe.length; i++) probe[i] = (byte) i;
                Signature signer = Signature.getInstance(jcaSigAlg);
                signer.initSign(privateKey);
                signer.update(probe);
                byte[] signature = signer.sign();
                Signature verifier = Signature.getInstance(jcaSigAlg);
                verifier.initVerify(chain[0].getPublicKey());
                verifier.update(probe);
                if (!verifier.verify(signature)) return "private key does not match certificate";
            } catch (Throwable t) {
                return "private key check failed: " + t.getMessage();
            }
            return null;
        }
    }

    static synchronized List<Entry> parseAll(List<String> base64List) {
        if (base64List == null || base64List.isEmpty()) return null;
        StringBuilder keyBuilder = new StringBuilder();
        for (String item : base64List) keyBuilder.append(item.length()).append(':').append(item.hashCode()).append(';');
        String cacheKey = keyBuilder.toString();
        if (cacheKey.equals(sCacheKey)) return CACHE.get(cacheKey);

        List<Entry> entries = new ArrayList<Entry>();
        for (String base64Xml : base64List) {
            try {
                if (base64Xml == null || base64Xml.isEmpty() || base64Xml.length() > MAX_BASE64) continue;
                byte[] xml = java.util.Base64.getMimeDecoder().decode(base64Xml);
                if (xml.length > MAX_XML) continue;
                entries.addAll(parseOne(xml));
            } catch (Throwable t) {
                Config.log("keybox parse failed", t);
            }
        }
        CACHE.clear();
        sCacheKey = cacheKey;
        CACHE.put(cacheKey, entries);
        return entries;
    }

    private static List<Entry> parseOne(byte[] xml) {
        List<Entry> entries = new ArrayList<Entry>();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(false);
            harden(factory);
            Document document = factory.newDocumentBuilder()
                    .parse(new ByteArrayInputStream(xml));
            NodeList keys = document.getElementsByTagName("Key");
            for (int i = 0; i < keys.getLength(); i++) {
                Node node = keys.item(i);
                if (!(node instanceof Element)) continue;
                Element keyElement = (Element) node;
                String algorithm = keyElement.getAttribute("algorithm");
                boolean ec = algorithm != null && algorithm.toLowerCase().contains("ec");
                boolean rsa = algorithm != null && algorithm.toLowerCase().contains("rsa");
                if (!ec && !rsa) continue;

                String privatePem = firstText(keyElement, "PrivateKey");
                List<String> certPems = certTexts(keyElement);
                if (privatePem == null || certPems.isEmpty()) continue;

                PrivateKey privateKey = parsePrivateKey(ec, privatePem);
                if (privateKey == null) continue;
                X509Certificate[] chain = parseCertificates(certPems);
                if (chain == null || chain.length == 0) continue;

                entries.add(new Entry(ec ? "EC" : "RSA", privateKey, chain,
                        ec ? EC_SIG_ALG : RSA_SIG_ALG, ec ? "SHA256withECDSA" : "SHA256withRSA"));
            }
        } catch (Throwable t) {
            Config.log("keybox XML parse failed", t);
        }
        return entries;
    }

    private static void harden(DocumentBuilderFactory factory) {
        try {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (Throwable ignored) {
        }
        try {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        } catch (Throwable ignored) {
        }
        try {
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        } catch (Throwable ignored) {
        }
        try {
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } catch (Throwable ignored) {
        }
        try {
            factory.setXIncludeAware(false);
        } catch (Throwable ignored) {
        }
        try {
            factory.setExpandEntityReferences(false);
        } catch (Throwable ignored) {
        }
    }

    /**
     * Picks a healthy keybox entry for the requested key algorithm. Falls back to the other
     * algorithm (RKP style) and finally to the first parsed entry so a broken keybox never
     * hard-fails attestation.
     */
    static Entry forAlgorithm(Config.Snapshot cfg, String algorithm) {
        List<Entry> entries = parseAll(cfg.keyboxList);
        if (entries == null || entries.isEmpty()) return null;

        List<Entry> ordered = new ArrayList<Entry>();
        int preferredIndex = cfg.keyboxIndexFor(Config.currentPackage());
        if (preferredIndex >= 0 && preferredIndex < entries.size()) {
            ordered.add(entries.get(preferredIndex));
        }
        boolean preferEc = algorithm == null || algorithm.toUpperCase().contains("EC");
        for (Entry entry : entries) {
            if (preferEc && "EC".equals(entry.algorithm)) ordered.add(entry);
        }
        for (Entry entry : entries) {
            if (!preferEc && "RSA".equals(entry.algorithm)) ordered.add(entry);
        }
        for (Entry entry : entries) ordered.add(entry);

        Entry fallback = entries.get(0);
        for (Entry entry : ordered) {
            if (entry == null) continue;
            if (fallback == null) fallback = entry;
            String problem = entry.problem();
            if (problem == null) return entry;
            Config.logOnce("keybox unhealthy: " + problem);
        }
        return fallback;
    }

    static boolean isIssuedBy(X509Certificate cert, Entry keybox) {
        try {
            return cert.getIssuerX500Principal().equals(keybox.chain[0].getSubjectX500Principal());
        } catch (Throwable t) {
            return false;
        }
    }

    static org.bouncycastle.asn1.x509.Certificate asn1(X509Certificate cert) {
        try {
            return Certificate.getInstance(cert.getEncoded());
        } catch (Throwable t) {
            return null;
        }
    }

    private static String firstText(Element parent, String tag) {
        NodeList list = parent.getElementsByTagName(tag);
        if (list.getLength() == 0) return null;
        String text = list.item(0).getTextContent();
        return text == null || text.trim().isEmpty() ? null : text;
    }

    private static List<String> certTexts(Element keyElement) {
        List<String> out = new ArrayList<String>();
        NodeList chains = keyElement.getElementsByTagName("CertificateChain");
        if (chains.getLength() == 0) {
            NodeList certs = keyElement.getElementsByTagName("Certificate");
            for (int i = 0; i < certs.getLength(); i++) out.add(certs.item(i).getTextContent());
            return out;
        }
        Element chain = (Element) chains.item(0);
        NodeList certs = chain.getElementsByTagName("Certificate");
        for (int i = 0; i < certs.getLength(); i++) out.add(certs.item(i).getTextContent());
        return out;
    }

    private static X509Certificate[] parseCertificates(List<String> pems) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> out = new ArrayList<X509Certificate>();
            for (String pem : pems) {
                if (pem == null || pem.trim().isEmpty()) continue;
                out.add((X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(pem.getBytes("UTF-8"))));
            }
            return out.toArray(new X509Certificate[0]);
        } catch (Throwable t) {
            Config.log("keybox certificate parse failed", t);
            return null;
        }
    }

    private static PrivateKey parsePrivateKey(boolean ec, String pem) {
        try {
            byte[] der = decodePem(pem);
            try {
                return KeyFactory.getInstance(ec ? "EC" : "RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(der));
            } catch (Throwable ignored) {
            }
            PrivateKeyInfo info;
            if (ec) {
                ECPrivateKey sec1 = ECPrivateKey.getInstance(der);
                ASN1Encodable params = sec1.getParametersObject();
                info = new PrivateKeyInfo(
                        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), sec1);
            } else {
                RSAPrivateKey pkcs1 = RSAPrivateKey.getInstance(der);
                info = new PrivateKeyInfo(
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                        pkcs1);
            }
            return KeyFactory.getInstance(ec ? "EC" : "RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded()));
        } catch (Throwable t) {
            Config.log("keybox private key parse failed", t);
            return null;
        }
    }

    static byte[] decodePem(String pem) {
        String cleaned = pem.replaceAll("-----BEGIN[^-]*-----", "")
                .replaceAll("-----END[^-]*-----", "")
                .replaceAll("\\s+", "");
        return java.util.Base64.getDecoder().decode(cleaned);
    }

    static SubjectPublicKeyInfo publicKeyInfo(X509Certificate cert) {
        try {
            org.bouncycastle.asn1.x509.Certificate asn1 = asn1(cert);
            if (asn1 == null) return null;
            return SubjectPublicKeyInfo.getInstance(asn1.getSubjectPublicKeyInfo().getEncoded());
        } catch (Throwable t) {
            return null;
        }
    }

    static ASN1Primitive primitive(byte[] der) {
        try {
            return ASN1Primitive.fromByteArray(der);
        } catch (Throwable t) {
            return null;
        }
    }
}
