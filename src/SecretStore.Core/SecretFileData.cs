namespace SecretStore.Core;

// Immutable value object carrying the raw cryptographic material extracted from a store file.
// Acts as a simple data-transfer struct between SecretFileReader (parsing) and
// SecretEncryptor (decryption) to keep those two concerns cleanly separated.
internal readonly struct SecretFileData
{
    internal SecretFileData(byte[] salt, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        Salt = salt;
        Nonce = nonce;
        Ciphertext = ciphertext;
        Tag = tag;
    }

    // PBKDF2 salt decoded from the JWE header's p2s field (16 bytes).
    internal readonly byte[] Salt;

    // AES-GCM nonce decoded from JWE segment [2] (12 bytes).
    internal readonly byte[] Nonce;

    // Encrypted secret payload decoded from JWE segment [3].
    internal readonly byte[] Ciphertext;

    // AES-GCM authentication tag decoded from JWE segment [4] (16 bytes).
    // Verified during decryption; a mismatch means a wrong password or file tampering.
    internal readonly byte[] Tag;
}
