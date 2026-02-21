package moe.kyokobot.libdave;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

// Ported from libdave test suite
public abstract class CryptorTestBase {
    // @formatter:off
    public static final byte[] RANDOM_BYTES = TestUtil.hexStringToByteArray(
        "0dc5aedd5bdc3f20be5697e54dd1f437b896a36f858c6f20bbd69e2a493ca170c4f0c1b9acd4" +
        "9d324b92afa788d09b12b29115a2feb3552b60fff983234a6c9608af3933683efc6b0f5579a9"
    );
    // @formatter:on

    abstract DaveFactory getDaveFactory();

    @Test
    public void passthroughInOutBuffer() {
        DaveFactory factory = getDaveFactory();

        ByteBuffer frameCopy = TestUtil.arrToDirectByteBuffer(RANDOM_BYTES);

        ByteBuffer frameViewIn = TestUtil.arrToDirectByteBuffer(RANDOM_BYTES);
        ByteBuffer frameViewOut = TestUtil.arrToDirectByteBuffer(RANDOM_BYTES);

        try (Encryptor encryptor = factory.createEncryptor()) {
            encryptor.assignSsrcToCodec(0, Codec.OPUS);
            encryptor.setPassthroughMode(true);

            int encryptResult = encryptor.encrypt(MediaType.AUDIO, 0, frameViewIn, frameViewOut);

            assertTrue(encryptResult >= 0);
            assertEquals(encryptResult, RANDOM_BYTES.length);
            assertEquals(0, frameViewIn.compareTo(frameCopy));
        }

        frameCopy.rewind();
        frameViewIn.rewind();
        frameViewOut.rewind();

        assertEquals(0, frameCopy.position());
        assertTrue(frameCopy.remaining() > 0);

        try (Decryptor decryptor = factory.createDecryptor()) {
            decryptor.transitionToPassthroughMode(true);

            int decryptResult = decryptor.decrypt(MediaType.AUDIO, frameViewIn, frameViewOut);

            assertTrue(decryptResult >= 0);
            assertEquals(decryptResult, RANDOM_BYTES.length);
            assertEquals(0, frameViewIn.compareTo(frameCopy));
        }
    }

    @Test
    public void passthroughTwoBuffers() {
        DaveFactory factory = getDaveFactory();

        ByteBuffer in = TestUtil.arrToDirectByteBuffer(RANDOM_BYTES);
        ByteBuffer encrypted = ByteBuffer.allocateDirect(RANDOM_BYTES.length * 2);
        ByteBuffer decrypted = ByteBuffer.allocateDirect(RANDOM_BYTES.length);

        try (Encryptor encryptor = factory.createEncryptor()) {
            encryptor.assignSsrcToCodec(0, Codec.OPUS);
            encryptor.setPassthroughMode(true);

            in.rewind();
            encrypted.rewind();

            int encryptResult = encryptor.encrypt(MediaType.AUDIO, 0, in, encrypted);

            assertEquals(RANDOM_BYTES.length, encryptResult);
            assertEquals(encryptResult, RANDOM_BYTES.length);

            // encrypted should now contain the original data for the first encryptResult bytes
            encrypted.rewind();
            for (int i = 0; i < encryptResult; i++) {
                assertEquals(RANDOM_BYTES[i], encrypted.get());
            }
        }

        // Now decrypt back
        encrypted.rewind();
        decrypted.rewind();
        try (Decryptor decryptor = factory.createDecryptor()) {
            decryptor.transitionToPassthroughMode(true);

            int decryptResult = decryptor.decrypt(MediaType.AUDIO, encrypted, decrypted);

            assertEquals(RANDOM_BYTES.length, decryptResult);
            assertEquals(decryptResult, RANDOM_BYTES.length);

            decrypted.rewind();
            for (int i = 0; i < decryptResult; i++) {
                assertEquals(RANDOM_BYTES[i], decrypted.get());
            }
        }
    }

}
