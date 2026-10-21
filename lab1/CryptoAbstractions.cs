namespace CryptographyLab1;

public interface IKeyExpansion
{
    byte[][] ExpandKey(byte[] inputKey);
}

public interface IEncryptionTransformation
{
    int InputBlockSize { get; }

    byte[] Transform(byte[] inputBlock, byte[] roundKey);
}

public interface ISymmetricCipher
{
    int BlockSize { get; }

    void SetKey(byte[] key);

    byte[] EncryptBlock(byte[] inputBlock);

    byte[] DecryptBlock(byte[] inputBlock);
}
