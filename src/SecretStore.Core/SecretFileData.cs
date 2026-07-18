namespace SecretStore.Core;

internal readonly struct SecretFileData
{
    internal SecretFileData(byte[] salt, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        Salt = salt;
        Nonce = nonce;
        Ciphertext = ciphertext;
        Tag = tag;
    }

    internal readonly byte[] Salt;
    internal readonly byte[] Nonce;
    internal readonly byte[] Ciphertext;
    internal readonly byte[] Tag;
}
