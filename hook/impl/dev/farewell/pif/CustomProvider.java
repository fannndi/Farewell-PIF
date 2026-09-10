package dev.farewell.pif;

import java.security.Provider;

/**
 * Wraps the real AndroidKeyStore provider so every service lookup re-applies the
 * spoofed Build fields (GMS occasionally restores them).
 */
public final class CustomProvider extends Provider {
    private static final long serialVersionUID = 1L;

    public CustomProvider(Provider base) {
        super(base.getName(), base.getVersion(), base.getInfo());
        putAll(base);
    }

    @Override
    public synchronized Service getService(String type, String algorithm) {
        try {
            Props.reapply();
        } catch (Throwable ignored) {
        }
        return super.getService(type, algorithm);
    }
}
