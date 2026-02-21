package moe.kyokobot.libdave;

public class CryptorTest extends CryptorTestBase {
    @Override
    DaveFactory getDaveFactory() {
        NativeDaveFactory.ensureAvailable();
        return new NativeDaveFactory();
    }
}
