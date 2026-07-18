using System.Security.Cryptography;

namespace SecretStore.Core;

// Handles all symmetric encryption and decryption for the secret store.
// Encryption scheme: PBKDF2-SHA512 key derivation → AES-256-GCM authenticated encryption.
internal static class SecretEncryptor
{
    // AES-256 requires a 256-bit (32-byte) key.
    private const int KeySize = 32;   // AES-256

    // 16-byte salt gives 128 bits of KDF uniqueness — sufficient to prevent rainbow-table
    // attacks across store files even if users choose the same password.
    private const int SaltSize = 16;

    // 12-byte nonce is the standard recommended size for AES-GCM (96-bit IV per NIST SP 800-38D).
    private const int NonceSize = 12;

    // 16-byte (128-bit) authentication tag is the maximum AES-GCM tag size, providing the
    // strongest integrity guarantee available.
    private const int TagSize = 16;

    // 310,000 iterations aligns with the OWASP 2023 recommendation for PBKDF2-SHA512.
    // A higher iteration count makes brute-force password attacks significantly more expensive.
    private const int Iterations = 310_000;

    private static readonly HashAlgorithmName KdfHash = HashAlgorithmName.SHA512;

    // Encrypts plaintext bytes using a freshly derived AES-256-GCM key.
    // A new salt and nonce are generated on every call, so identical plaintexts
    // produce different ciphertexts — this prevents ciphertext comparison attacks.
    internal static void Encrypt(ReadOnlySpan<byte> plaintext, string password, out byte[] salt, out byte[] nonce, out byte[] ciphertext, out byte[] tag)
    {
        // Generate cryptographically random salt and nonce for this encryption operation.
        // Never reuse a nonce with the same key under AES-GCM — doing so would break confidentiality.
        salt = RandomNumberGenerator.GetBytes(SaltSize);
        nonce = RandomNumberGenerator.GetBytes(NonceSize);

        // Allocate the key on the stack to avoid heap allocation and reduce the window during
        // which the key bytes are reachable by a garbage-collection scan or memory dump.
        Span<byte> key = stackalloc byte[KeySize];
        DeriveKey(password, salt, key);

        ciphertext = new byte[plaintext.Length];
        tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Zero the key material immediately after use so it does not linger in process memory.
        CryptographicOperations.ZeroMemory(key);
    }

    // Decrypts ciphertext using AES-256-GCM and verifies its authentication tag.
    // If the tag does not match (wrong password or tampered file), a CryptographicException
    // is thrown with a user-friendly message rather than the raw AuthenticationTagMismatchException,
    // to avoid leaking implementation details.
    internal static byte[] Decrypt(string password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
    {
        // Stack-allocate the key for the same reason as in Encrypt — minimise heap exposure.
        Span<byte> key = stackalloc byte[KeySize];
        DeriveKey(password, salt, key);

        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch (AuthenticationTagMismatchException)
        {
            // Wrap with a friendlier message. A tag mismatch has two possible causes:
            // 1. The user provided the wrong master password.
            // 2. The store file has been corrupted or tampered with.
            throw new CryptographicException("Authentication failed: wrong password or corrupted file.");
        }
        finally
        {
            // Always zero the key, even if decryption throws, to prevent key material leaking
            // through an unhandled exception path.
            CryptographicOperations.ZeroMemory(key);
        }

        return plaintext;
    }

    // Derives a symmetric encryption key from the master password and salt using PBKDF2-SHA512.
    // The salt must be the same value that was used during encryption; it is stored in the JWE header.
    private static void DeriveKey(string password, ReadOnlySpan<byte> salt, Span<byte> key)
    {
        // Rfc2898DeriveBytes.Pbkdf2 does not accept a ReadOnlySpan<byte> salt directly in all
        // target framework versions, so a temporary array copy is required here.
        // The copy is zeroed immediately after the KDF completes.
        var saltArray = salt.ToArray();

        Rfc2898DeriveBytes.Pbkdf2(password, saltArray, key, Iterations, KdfHash);
        CryptographicOperations.ZeroMemory(saltArray);
    }
}
