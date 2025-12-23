package moe.kyokobot.libdave;

import moe.kyokobot.libdave.callbacks.MLSFailureCallback;
import moe.kyokobot.libdave.impl.NativeDecryptor;
import moe.kyokobot.libdave.impl.NativeEncryptor;
import moe.kyokobot.libdave.impl.NativeSession;
import moe.kyokobot.libdave.natives.DaveNativeBindings;

public class NativeDaveFactory implements DaveFactory {
    /**
     * Loads the native library and ensures that {@link NativeDaveFactory} can be used on this platform.
     *
     * @throws {@link RuntimeException} if the native library could not be loaded and the factory is not safe to use.
     */
    public static void ensureAvailable() throws RuntimeException {
        try {
            DaveNativeBindings.inst();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("DAVE Native bindings could not be loaded!", e);
        }
    }

    @Override
    public int maxSupportedProtocolVersion() {
        return DaveNativeBindings.inst().daveMaxSupportedProtocolVersion();
    }

    @Override
    public Decryptor createDecryptor() {
        long handle = DaveNativeBindings.inst().daveDecryptorCreate();
        return new NativeDecryptor(handle);
    }

    @Override
    public Encryptor createEncryptor() {
        long handle = DaveNativeBindings.inst().daveEncryptorCreate();
        return new NativeEncryptor(handle);
    }

    @Override
    public Session createSession(String context, String authSessionId, MLSFailureCallback callback) {
        long handle = DaveNativeBindings.inst().daveSessionCreate(context, authSessionId, callback);
        return new NativeSession(handle);
    }
}
