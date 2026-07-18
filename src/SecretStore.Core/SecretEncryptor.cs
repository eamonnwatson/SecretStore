using System.Security.Cryptography;

namespace SecretStore.Core;

internal static class SecretEncryptor
{
    private const int KeySize = 32;   // AES-256
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int Iterations = 310_000;
    private static readonly HashAlgorithmName KdfHash = HashAlgorithmName.SHA512;

    internal static void Encrypt(ReadOnlySpan<byte> plaintext, string password, out byte[] salt, out byte[] nonce, out byte[] ciphertext, out byte[] tag)
    {
        salt = RandomNumberGenerator.GetBytes(SaltSize);
        nonce = RandomNumberGenerator.GetBytes(NonceSize);

        Span<byte> key = stackalloc byte[KeySize];
        DeriveKey(password, salt, key);

        ciphertext = new byte[plaintext.Length];
        tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        CryptographicOperations.ZeroMemory(key);
    }

    internal static byte[] Decrypt(string password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
    {
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
            throw new CryptographicException("Authentication failed: wrong password or corrupted file.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        return plaintext;
    }

    private static void DeriveKey(string password, ReadOnlySpan<byte> salt, Span<byte> key)
    {
        var saltArray = salt.ToArray();

        Rfc2898DeriveBytes.Pbkdf2(password, saltArray, key, Iterations, KdfHash);
        CryptographicOperations.ZeroMemory(saltArray);
    }
}
