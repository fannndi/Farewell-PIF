package dev.farewell.pif;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * KeyMint / keymaster attestation record handling.
 *
 * The extension value is a DER `KeyDescription`:
 *
 * <pre>
 * SEQUENCE {
 *   [701] EXPLICIT INTEGER    attestationVersion
 *   [702] EXPLICIT ENUMERATED attestationSecurityLevel
 *   [703] EXPLICIT INTEGER    keymasterVersion
 *   [704] EXPLICIT ENUMERATED keymasterSecurityLevel
 *   [705] EXPLICIT OCTET STRING attestationChallenge
 *   [706] EXPLICIT OCTET STRING uniqueId
 *   SEQUENCE {}               softwareEnforced
 *   SEQUENCE {}               teeEnforced
 * }
 * </pre>
 *
 * Patch mode rewrites the root of trust, OS / vendor / boot patch levels and the device
 * property attestation tags inside the two enforcement lists only (the meta fields share
 * tag numbers with keymaster tags, so scoping matters), then re-signs the leaf with the
 * keybox key. Generate mode builds the whole KeyDescription from scratch.
 */
final class Attestation {
    static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    static final int TAG_ROOT_OF_TRUST = 704;
    static final int TAG_OS_VERSION = 705;
    static final int TAG_OS_PATCHLEVEL = 706;
    static final int TAG_ATTESTATION_APPLICATION_ID = 709;
    static final int TAG_ID_BRAND = 710;
    static final int TAG_ID_DEVICE = 711;
    static final int TAG_ID_PRODUCT = 712;
    static final int TAG_ID_SERIAL = 713;
    static final int TAG_ID_IMEI = 714;
    static final int TAG_ID_MEID = 715;
    static final int TAG_ID_MANUFACTURER = 716;
    static final int TAG_ID_MODEL = 717;
    static final int TAG_VENDOR_PATCHLEVEL = 718;
    static final int TAG_BOOT_PATCHLEVEL = 719;

    private static final int[] INSERTABLE_TAGS = {
            TAG_ROOT_OF_TRUST, TAG_OS_VERSION, TAG_OS_PATCHLEVEL,
            TAG_VENDOR_PATCHLEVEL, TAG_BOOT_PATCHLEVEL
    };

    private static final SecureRandom RNG = new SecureRandom();

    private Attestation() {
    }

    static X509Certificate parseCertificate(byte[] der) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
        } catch (Throwable t) {
            return null;
        }
    }

    /** Patch a real TEE leaf (keeps its public key, serial, subject, validity). */
    static byte[] forgeLeaf(X509Certificate real, Keybox.Entry kb, Config.Snapshot cfg,
                            byte[] challenge, boolean idsRequested, KeyParams params) {
        try {
            org.json.JSONObject profile = cfg.profileFor(Config.currentPackage());
            byte[] forgedExt;
            byte[] realExt = real.getExtensionValue(ATTESTATION_OID);
            if (realExt != null) {
                byte[] value = ASN1OctetString.getInstance(realExt).getOctets();
                forgedExt = transformExtension(value, cfg, profile);
                if (forgedExt == null) return null;
            } else {
                forgedExt = buildKeyDescription(challenge, cfg, profile, idsRequested, params);
                if (forgedExt == null) return null;
            }
            return resignLeaf(real, kb, forgedExt, false, null);
        } catch (Throwable t) {
            Config.log("forgeLeaf failed", t);
            return null;
        }
    }

    /** Build a brand new leaf for a software public key (TEE broken / generate mode). */
    static byte[] forgeSoftwareLeaf(PublicKey publicKey, Keybox.Entry kb, Config.Snapshot cfg,
                                    byte[] challenge, boolean idsRequested, KeyParams params) {
        try {
            org.json.JSONObject profile = cfg.profileFor(Config.currentPackage());
            byte[] forgedExt = buildKeyDescription(challenge, cfg, profile, idsRequested, params);
            if (forgedExt == null) return null;
            return resignLeaf(null, kb, forgedExt, true, publicKey);
        } catch (Throwable t) {
            Config.log("forgeSoftwareLeaf failed", t);
            return null;
        }
    }

    /**
     * Key characteristics from the generation request, emitted like stock Android does.
     * TEESimulator-RS writes purpose/algorithm/keySize/digest/curve/origin into the record;
     * omitting them makes the attestation look unlike a real TEE one.
     */
    static final class KeyParams {
        static final KeyParams DEFAULT_EC = new KeyParams(
                new int[]{2, 3}, 3, 256, new int[]{4}, Integer.valueOf(1), true);

        final int[] purposes;
        final int algorithm;
        final int keySize;
        final int[] digests;
        final Integer ecCurve;
        final boolean noAuthRequired;

        KeyParams(int[] purposes, int algorithm, int keySize, int[] digests,
                  Integer ecCurve, boolean noAuthRequired) {
            this.purposes = purposes;
            this.algorithm = algorithm;
            this.keySize = keySize;
            this.digests = digests;
            this.ecCurve = ecCurve;
            this.noAuthRequired = noAuthRequired;
        }

        static KeyParams from(android.security.keystore.KeyGenParameterSpec spec,
                              int kmAlgorithm, int keySize) {
            int[] purposes = spec != null ? mapPurposes(spec.getPurposes()) : null;
            int[] digests = spec != null ? mapDigests(spec.getDigests()) : null;
            Boolean noAuth = spec != null
                    ? Boolean.valueOf(!spec.isUserAuthenticationRequired()) : Boolean.TRUE;
            if (purposes == null || purposes.length == 0) purposes = new int[]{2, 3};
            if (digests == null || digests.length == 0) digests = new int[]{4};
            Integer curve = kmAlgorithm == 3 ? Integer.valueOf(1) : null; // P-256
            return new KeyParams(purposes, kmAlgorithm, keySize, digests, curve,
                    noAuth.booleanValue());
        }

        /** KeyProperties purpose bits -> KeyMint KeyPurpose enum values. */
        private static int[] mapPurposes(int bits) {
            java.util.List<Integer> out = new java.util.ArrayList<Integer>();
            int[] flags = {1, 2, 4, 8, 32, 64, 128};
            int[] values = {0, 1, 2, 3, 4, 5, 6};
            for (int i = 0; i < flags.length; i++) {
                if ((bits & flags[i]) != 0) out.add(Integer.valueOf(values[i]));
            }
            int[] result = new int[out.size()];
            for (int i = 0; i < result.length; i++) result[i] = out.get(i).intValue();
            return result;
        }

        /** KeyProperties digest names -> KeyMint Digest enum values. */
        private static int[] mapDigests(String[] names) {
            if (names == null) return null;
            java.util.List<Integer> out = new java.util.ArrayList<Integer>();
            for (String name : names) {
                if (name == null) continue;
                switch (name) {
                    case "SHA-1": out.add(Integer.valueOf(2)); break;
                    case "SHA-224": out.add(Integer.valueOf(3)); break;
                    case "SHA-256": out.add(Integer.valueOf(4)); break;
                    case "SHA-384": out.add(Integer.valueOf(5)); break;
                    case "SHA-512": out.add(Integer.valueOf(6)); break;
                    default: break;
                }
            }
            int[] result = new int[out.size()];
            for (int i = 0; i < result.length; i++) result[i] = out.get(i).intValue();
            return result;
        }
    }

    private static byte[] resignLeaf(X509Certificate real, Keybox.Entry kb, byte[] forgedExt,
                                     boolean software, PublicKey softwareKey) throws Exception {
        org.bouncycastle.asn1.x509.Certificate kbCert = Keybox.asn1(kb.chain[0]);
        if (kbCert == null) return null;

        V3TBSCertificateGenerator generator = new V3TBSCertificateGenerator();
        Extensions extensions;
        if (software) {
            byte[] serial = new byte[16];
            RNG.nextBytes(serial);
            serial[0] = (byte) (serial[0] & 0x7f);
            generator.setSerialNumber(new ASN1Integer(new BigInteger(1, serial)));
            generator.setSubject(kbCert.getSubject());
            generator.setStartDate(kbCert.getStartDate());
            generator.setEndDate(kbCert.getEndDate());
            generator.setSubjectPublicKeyInfo(
                    SubjectPublicKeyInfo.getInstance(softwareKey.getEncoded()));
            extensions = new Extensions(new Extension[]{
                    new Extension(new ASN1ObjectIdentifier(ATTESTATION_OID), false,
                            new DEROctetString(forgedExt))});
        } else {
            org.bouncycastle.asn1.x509.Certificate realAsn1 =
                    org.bouncycastle.asn1.x509.Certificate.getInstance(real.getEncoded());
            TBSCertificate tbs = realAsn1.getTBSCertificate();
            generator.setSerialNumber(tbs.getSerialNumber());
            generator.setSubject(tbs.getSubject());
            generator.setStartDate(tbs.getStartDate());
            generator.setEndDate(tbs.getEndDate());
            generator.setSubjectPublicKeyInfo(tbs.getSubjectPublicKeyInfo());
            extensions = replaceAttestationExtension(tbs.getExtensions(), forgedExt);
        }
        generator.setIssuer(kbCert.getSubject());
        generator.setSignature(kb.sigAlg);
        generator.setExtensions(extensions);

        byte[] tbsDer = generator.generateTBSCertificate().getEncoded(ASN1Encoding.DER);

        Signature signer = Signature.getInstance(kb.jcaSigAlg);
        signer.initSign(kb.privateKey);
        signer.update(tbsDer);
        byte[] signature = signer.sign();

        ASN1EncodableVector cert = new ASN1EncodableVector();
        cert.add(ASN1Primitive.fromByteArray(tbsDer));
        cert.add(kb.sigAlg);
        cert.add(new DERBitString(signature));
        return new DERSequence(cert).getEncoded(ASN1Encoding.DER);
    }

    private static Extensions replaceAttestationExtension(Extensions original, byte[] forgedExt)
            throws Exception {
        Extension attestation = new Extension(
                new ASN1ObjectIdentifier(ATTESTATION_OID), false, new DEROctetString(forgedExt));
        if (original == null) {
            return new Extensions(new Extension[]{attestation});
        }
        List<Extension> out = new ArrayList<Extension>();
        boolean replaced = false;
        for (ASN1ObjectIdentifier oid : original.getExtensionOIDs()) {
            if (ATTESTATION_OID.equals(oid.getId())) {
                out.add(attestation);
                replaced = true;
            } else {
                out.add(original.getExtension(oid));
            }
        }
        if (!replaced) out.add(attestation);
        return new Extensions(out.toArray(new Extension[0]));
    }

    private static byte[] transformExtension(byte[] value, Config.Snapshot cfg,
                                             org.json.JSONObject profile) {
        try {
            ASN1Sequence description = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(value));
            if (description.size() != 8) return null;
            List<ASN1Encodable> seen = new ArrayList<ASN1Encodable>();
            ASN1Encodable software = replaceInList(description.getObjectAt(6), cfg, profile, seen);
            ASN1Encodable hardware = replaceInList(description.getObjectAt(7), cfg, profile, seen);
            hardware = insertMissing(hardware, cfg, profile, seen);
            if (software == null || hardware == null) return null;
            ASN1EncodableVector out = new ASN1EncodableVector();
            for (int i = 0; i < 6; i++) out.add(description.getObjectAt(i));
            out.add(software);
            out.add(hardware);
            return new DERSequence(out).getEncoded(ASN1Encoding.DER);
        } catch (Throwable t) {
            Config.log("attestation transform failed", t);
            return null;
        }
    }

    private static ASN1Encodable replaceInList(ASN1Encodable listEncodable, Config.Snapshot cfg,
                                               org.json.JSONObject profile,
                                               List<ASN1Encodable> seen) {
        if (!(listEncodable instanceof ASN1Sequence)) return null;
        ASN1Sequence list = (ASN1Sequence) listEncodable;
        ASN1EncodableVector out = new ASN1EncodableVector();
        for (int i = 0; i < list.size(); i++) {
            ASN1Encodable element = list.getObjectAt(i);
            Integer tag = tagNumber(element);
            ASN1Encodable replacement = tag != null
                    ? overrideFor(tag.intValue(), cfg, profile) : null;
            if (replacement != null) {
                out.add(replacement);
                seen.add(replacement);
            } else {
                out.add(element);
                if (tag != null) seen.add(element);
            }
        }
        return new DERSequence(out);
    }

    private static ASN1Encodable insertMissing(ASN1Encodable listEncodable, Config.Snapshot cfg,
                                               org.json.JSONObject profile,
                                               List<ASN1Encodable> seen) {
        if (!(listEncodable instanceof ASN1Sequence)) return null;
        ASN1Sequence list = (ASN1Sequence) listEncodable;
        List<ASN1Encodable> elements = new ArrayList<ASN1Encodable>();
        for (int i = 0; i < list.size(); i++) elements.add(list.getObjectAt(i));
        for (int tag : INSERTABLE_TAGS) {
            if (containsTag(seen, tag) || containsTag(elements, tag)) continue;
            ASN1Encodable replacement = overrideFor(tag, cfg, profile);
            if (replacement != null) elements.add(replacement);
        }
        java.util.Collections.sort(elements, new java.util.Comparator<ASN1Encodable>() {
            @Override
            public int compare(ASN1Encodable left, ASN1Encodable right) {
                Integer l = tagNumber(left);
                Integer r = tagNumber(right);
                int lv = l != null ? l.intValue() : Integer.MAX_VALUE;
                int rv = r != null ? r.intValue() : Integer.MAX_VALUE;
                return lv < rv ? -1 : (lv == rv ? 0 : 1);
            }
        });
        ASN1EncodableVector out = new ASN1EncodableVector();
        for (ASN1Encodable element : elements) out.add(element);
        return new DERSequence(out);
    }

    private static boolean containsTag(List<ASN1Encodable> elements, int tag) {
        for (ASN1Encodable element : elements) {
            Integer value = tagNumber(element);
            if (value != null && value.intValue() == tag) return true;
        }
        return false;
    }

    private static Integer tagNumber(ASN1Encodable element) {
        if (element instanceof ASN1TaggedObject) {
            return Integer.valueOf(((ASN1TaggedObject) element).getTagNo());
        }
        return null;
    }

    private static ASN1Encodable overrideFor(int tag, Config.Snapshot cfg,
                                             org.json.JSONObject profile) {
        switch (tag) {
            case TAG_ROOT_OF_TRUST:
                return new DERTaggedObject(true, tag, buildRootOfTrust(cfg));
            case TAG_OS_VERSION:
                return explicitInteger(tag, cfg.osVersion());
            case TAG_OS_PATCHLEVEL:
                return explicitInteger(tag, cfg.osPatchLevel(profile));
            case TAG_VENDOR_PATCHLEVEL: {
                // TEESimulator's security_patch.txt default: vendor=device_default.
                int[] real = parsePatch(NativeProps.realProperty("ro.vendor.build.security_patch"));
                if (real != null) return explicitInteger(tag, real[0] * 100 + real[1]);
                return explicitInteger(tag, cfg.patchLevelDay(profile));
            }
            case TAG_BOOT_PATCHLEVEL:
                // TEESimulator's default is boot=no: the field is omitted.
                return null;
            default:
                if (tag >= TAG_ID_BRAND && tag <= TAG_ID_MODEL) {
                    String value = cfg.devicePropForTag(tag, profile);
                    if (value != null && !value.isEmpty()) {
                        return explicitOctetString(tag, value);
                    }
                }
                if (tag == TAG_ID_SERIAL || tag == TAG_ID_IMEI || tag == TAG_ID_MEID) {
                    String value = Config.Snapshot.profileString(profile, idTagName(tag));
                    if (value != null && !value.isEmpty()) {
                        return explicitOctetString(tag, value);
                    }
                }
                return null;
        }
    }

    private static int[] parsePatch(String value) {
        if (value == null) return null;
        try {
            String[] parts = value.trim().split("-");
            if (parts.length < 2) return null;
            return new int[]{Integer.parseInt(parts[0]), Integer.parseInt(parts[1])};
        } catch (Throwable t) {
            return null;
        }
    }

    private static String idTagName(int tag) {
        switch (tag) {
            case TAG_ID_SERIAL:
                return "SERIAL";
            case TAG_ID_IMEI:
                return "IMEI";
            case TAG_ID_MEID:
                return "MEID";
            default:
                return "";
        }
    }

    private static ASN1Encodable explicitInteger(int tag, int value) {
        return new DERTaggedObject(true, tag, new ASN1Integer(value));
    }

    private static ASN1Encodable explicitOctetString(int tag, String value) {
        try {
            return new DERTaggedObject(true, tag, new DEROctetString(value.getBytes("UTF-8")));
        } catch (Throwable t) {
            return new DERTaggedObject(true, tag, new DEROctetString(new byte[0]));
        }
    }

    static byte[] buildKeyDescription(byte[] challenge, Config.Snapshot cfg,
                                      org.json.JSONObject profile, boolean idsRequested,
                                      KeyParams params) {
        try {
            int attestationVersion = cfg.attestationVersion();
            int keymasterVersion = cfg.keymasterVersion();

            // Meta fields are positional (no context tags) per KeyMint key generation:
            // INTEGER, ENUMERATED, INTEGER, ENUMERATED, OCTET STRING, OCTET STRING, then two
            // untagged authorization list SEQUENCEs.
            ASN1EncodableVector description = new ASN1EncodableVector();
            description.add(new ASN1Integer(attestationVersion));
            description.add(new ASN1Enumerated(1));
            description.add(new ASN1Integer(keymasterVersion));
            description.add(new ASN1Enumerated(1));
            description.add(new DEROctetString(challenge != null ? challenge : new byte[0]));
            description.add(new DEROctetString(new byte[0]));

            // softwareEnforced: CREATION_DATETIME (701), ATTESTATION_APPLICATION_ID (709).
            ASN1EncodableVector software = new ASN1EncodableVector();
            software.add(new DERTaggedObject(true, 701,
                    new ASN1Integer(System.currentTimeMillis())));
            byte[] applicationId = buildApplicationId(cfg);
            if (applicationId != null) {
                software.add(new DERTaggedObject(true, TAG_ATTESTATION_APPLICATION_ID,
                        new DEROctetString(applicationId)));
            }
            description.add(new DERSequence(software));

            // teeEnforced, sorted by tag number exactly like stock Android emits it.
            ASN1EncodableVector hardware = new ASN1EncodableVector();
            if (params != null && params.purposes.length > 0) {
                ASN1EncodableVector set = new ASN1EncodableVector();
                for (int purpose : params.purposes) set.add(new ASN1Integer(purpose));
                hardware.add(new DERTaggedObject(true, 1,
                        new org.bouncycastle.asn1.DERSet(set)));
            }
            if (params != null) {
                hardware.add(explicitInteger(2, params.algorithm));
                hardware.add(explicitInteger(3, params.keySize));
                if (params.digests.length > 0) {
                    ASN1EncodableVector set = new ASN1EncodableVector();
                    for (int digest : params.digests) set.add(new ASN1Integer(digest));
                    hardware.add(new DERTaggedObject(true, 5,
                            new org.bouncycastle.asn1.DERSet(set)));
                }
                if (params.ecCurve != null) {
                    hardware.add(explicitInteger(10, params.ecCurve.intValue()));
                }
                if (params.noAuthRequired) {
                    hardware.add(new DERTaggedObject(true, 503,
                            org.bouncycastle.asn1.DERNull.INSTANCE));
                }
            }
            hardware.add(explicitInteger(702, 0));
            addIfPresent(hardware, overrideFor(TAG_ROOT_OF_TRUST, cfg, profile));
            addIfPresent(hardware, overrideFor(TAG_OS_VERSION, cfg, profile));
            addIfPresent(hardware, overrideFor(TAG_OS_PATCHLEVEL, cfg, profile));
            if (idsRequested) {
                int[] idTags = {TAG_ID_BRAND, TAG_ID_DEVICE, TAG_ID_PRODUCT, TAG_ID_SERIAL,
                        TAG_ID_IMEI, TAG_ID_MEID, TAG_ID_MANUFACTURER, TAG_ID_MODEL};
                for (int tag : idTags) {
                    String value = tag >= TAG_ID_SERIAL && tag <= TAG_ID_MEID
                            ? Config.Snapshot.profileString(profile, idTagName(tag))
                            : cfg.devicePropForTag(tag, profile);
                    if (value != null && !value.isEmpty()) {
                        hardware.add(explicitOctetString(tag, value));
                    }
                }
            }
            addIfPresent(hardware, overrideFor(TAG_VENDOR_PATCHLEVEL, cfg, profile));
            addIfPresent(hardware, overrideFor(TAG_BOOT_PATCHLEVEL, cfg, profile));
            description.add(new DERSequence(hardware));
            return new DERSequence(description).getEncoded(ASN1Encoding.DER);
        } catch (Throwable t) {
            Config.log("buildKeyDescription failed", t);
            return null;
        }
    }

    /** Extracts the attestationChallenge (KeyDescription field [4]) from a forged/real leaf. */
    static byte[] challengeOf(X509Certificate cert) {
        try {
            byte[] extension = cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
            if (extension == null) return null;
            ASN1OctetString wrapped = ASN1OctetString.getInstance(extension);
            ASN1Sequence description = ASN1Sequence.getInstance(wrapped.getOctets());
            if (description.size() <= 4) return null;
            ASN1Encodable challenge = description.getObjectAt(4);
            if (challenge instanceof ASN1OctetString) {
                return ((ASN1OctetString) challenge).getOctets();
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** AuthorizationList entries are omitted when the override decided not to report a field. */
    private static void addIfPresent(ASN1EncodableVector vector, ASN1Encodable element) {
        if (element != null) vector.add(element);
    }

    /**
     * Best effort AttestationApplicationId:
     * SEQUENCE { SET OF SEQUENCE { packageName OCTET STRING, version INTEGER },
     *            SET OF OCTET STRING signatureDigests }.
     */
    private static byte[] buildApplicationId(Config.Snapshot cfg) {
        try {
            android.content.Context context = Config.context();
            if (context == null) return null;
            String packageName = context.getPackageName();
            if (packageName == null) return null;

            ASN1EncodableVector record = new ASN1EncodableVector();
            record.add(new DEROctetString(packageName.getBytes("UTF-8")));
            record.add(new ASN1Integer(0));
            ASN1EncodableVector records = new ASN1EncodableVector();
            records.add(new DERSequence(record));

            ASN1EncodableVector digests = new ASN1EncodableVector();
            try {
                android.content.pm.PackageInfo info = context.getPackageManager()
                        .getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES);
                android.content.pm.SigningInfo signing = info.signingInfo;
                android.content.pm.Signature[] signatures = signing != null
                        ? signing.getApkContentsSigners() : info.signatures;
                if (signatures != null && signatures.length > 0) {
                    java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                    digests.add(new DEROctetString(digest.digest(signatures[0].toByteArray())));
                }
            } catch (Throwable ignored) {
            }

            ASN1EncodableVector applicationId = new ASN1EncodableVector();
            applicationId.add(new org.bouncycastle.asn1.DERSet(records));
            applicationId.add(new org.bouncycastle.asn1.DERSet(digests));
            return new DERSequence(applicationId).getEncoded(ASN1Encoding.DER);
        } catch (Throwable t) {
            return null;
        }
    }

    private static ASN1Encodable buildRootOfTrust(Config.Snapshot cfg) {
        ASN1EncodableVector out = new ASN1EncodableVector();
        out.add(new DEROctetString(cfg.verifiedBootKey()));
        out.add(ASN1Boolean.TRUE);
        out.add(new ASN1Enumerated(0));
        out.add(new DEROctetString(cfg.verifiedBootHash()));
        return new DERSequence(out);
    }
}
