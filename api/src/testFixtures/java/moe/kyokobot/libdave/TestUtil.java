package moe.kyokobot.libdave;

import java.nio.ByteBuffer;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

public class TestUtil {
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static ByteBuffer arrToDirectByteBuffer(byte[] arr) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(arr.length);
        buffer.put(arr);
        buffer.flip();
        return buffer;
    }

    public static ByteBuf arrToDirectByteBuf(byte[] arr) {
        ByteBuf buffer = Unpooled.directBuffer(arr.length);
        buffer.writeBytes(arr);
        return buffer;
    }
}
