package moe.kyokobot.libdave.impl;

import moe.kyokobot.libdave.Decryptor;
import moe.kyokobot.libdave.KeyRatchet;
import moe.kyokobot.libdave.MediaType;
import moe.kyokobot.libdave.natives.DaveNativeBindings;

import java.nio.ByteBuffer;

public class NativeDecryptor extends DaveNativeHandle implements Decryptor {
    public NativeDecryptor(long handle) {
        super(handle);
    }

    @Override
    public void transitionToKeyRatchet(KeyRatchet keyRatchet) {
        assertOpen();
        if (keyRatchet instanceof NativeKeyRatchet) {
            NativeKeyRatchet nativeRatchet = (NativeKeyRatchet) keyRatchet;
            DaveNativeBindings.inst().daveDecryptorTransitionToKeyRatchet(handle, nativeRatchet.getHandle());
        } else {
            throw new IllegalArgumentException("The passed KeyRatchet was not created by native Session!");
        }
    }

    @Override
    public void transitionToPassthroughMode(boolean passthroughMode) {
        assertOpen();
        DaveNativeBindings.inst().daveDecryptorTransitionToPassthroughMode(handle, passthroughMode);
    }

    @Override
    public long getMaxPlaintextByteSize(MediaType mediaType, long encryptedFrameSize) {
        assertOpen();
        return DaveNativeBindings.inst().daveDecryptorGetMaxPlaintextByteSize(handle, mediaType.getValue(), encryptedFrameSize);
    }

    @Override
    public int decrypt(MediaType mediaType, byte[] encryptedFrame, byte[] frame) {
        assertOpen();
        return DaveNativeBindings.inst().daveDecryptorDecrypt(handle, mediaType.getValue(), encryptedFrame, frame);
    }

    @Override
    public int decrypt(MediaType mediaType, ByteBuffer encryptedFrame, ByteBuffer frame) {
        assertOpen();
        return DaveNativeBindings.inst().daveDecryptorDecrypt(handle, mediaType.getValue(), encryptedFrame, frame);
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        DaveNativeBindings.inst().daveDecryptorDestroy(handle);
    }
}

