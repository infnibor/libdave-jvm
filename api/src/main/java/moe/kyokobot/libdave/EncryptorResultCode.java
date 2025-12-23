package moe.kyokobot.libdave;

/**
 * Result codes for {@link Encryptor#encrypt} operations.
 */
public enum EncryptorResultCode {
    /**
     * Encryption was successful.
     */
    SUCCESS(0),
    /**
     * Encryption failed (generic error).
     */
    ENCRYPTION_FAILURE(1);

    private final int value;

    EncryptorResultCode(int value) {
        this.value = value;
    }

    /**
     * Gets the integer value of the result code.
     *
     * @return The result code value.
     */
    public int getValue() {
        return value;
    }

    /**
     * Retrieves the EncryptorResultCode enum from its integer value.
     *
     * @param value The integer value.
     * @return The corresponding {@link EncryptorResultCode}.
     * @throws IllegalArgumentException if the value is unknown.
     */
    public static EncryptorResultCode fromValue(int value) {
        for (EncryptorResultCode code : values()) {
            if (code.value == value) {
                return code;
            }
        }
        throw new IllegalArgumentException("Unknown EncryptorResultCode value: " + value);
    }
}

