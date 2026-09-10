package dev.farewell.pif;

import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Parcel;
import android.os.Parcelable;

import java.lang.reflect.Field;

/**
 * Replaces the platform ("android") package signature with the Google release
 * signature. Only needed when the ROM is signed with a non official key.
 */
public final class CustomPackageInfoCreator implements Parcelable.Creator<PackageInfo> {
    private final Parcelable.Creator<PackageInfo> original;
    private final Signature spoofed;

    public CustomPackageInfoCreator(Parcelable.Creator<PackageInfo> original, Signature spoofed) {
        this.original = original;
        this.spoofed = spoofed;
    }

    @Override
    public PackageInfo createFromParcel(Parcel source) {
        PackageInfo info = original.createFromParcel(source);
        if (info == null || !"android".equals(info.packageName)) return info;
        try {
            if (info.signatures != null && info.signatures.length > 0) {
                info.signatures[0] = spoofed;
            }
        } catch (Throwable ignored) {
        }
        try {
            SigningInfo signingInfo = info.signingInfo;
            if (signingInfo != null) {
                Field detailsField = Props.findField(SigningInfo.class, "mSigningDetails");
                detailsField.setAccessible(true);
                Object details = detailsField.get(signingInfo);
                if (details != null) {
                    Field signaturesField = Props.findField(details.getClass(), "signatures");
                    signaturesField.setAccessible(true);
                    signaturesField.set(details, new Signature[]{spoofed});
                }
            }
        } catch (Throwable ignored) {
        }
        return info;
    }

    @Override
    public PackageInfo[] newArray(int size) {
        return original.newArray(size);
    }
}
