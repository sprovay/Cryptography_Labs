namespace CryptographyLab1;

public sealed class FeistelNetwork : ISymmetricCipher
{
    private readonly IKeyExpansion _keyExpansion;
    private readonly IEncryptionTransformation _transformation;
    private byte[][]? _roundKeys;

    public FeistelNetwork(
        IKeyExpansion keyExpansion,
        IEncryptionTransformation transformation)
    {
        ArgumentNullException.ThrowIfNull(keyExpansion);
        ArgumentNullException.ThrowIfNull(transformation);

        if (transformation.InputBlockSize <= 0 ||
            transformation.InputBlockSize > int.MaxValue / 2)
        {
            throw new ArgumentOutOfRangeException(
                nameof(transformation),
                "The transformation input block size must be positive.");
        }

        _keyExpansion = keyExpansion;
        _transformation = transformation;
    }

    public int BlockSize => _transformation.InputBlockSize * 2;

    public void SetKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _roundKeys = ExpandAndValidateKey(key);
    }

    public byte[] EncryptBlock(byte[] inputBlock)
    {
        ArgumentNullException.ThrowIfNull(inputBlock);
        ValidateBlockSize(inputBlock);

        byte[][] roundKeys = _roundKeys
            ?? throw new InvalidOperationException(
                "The key has not been configured.");

        int halfSize = _transformation.InputBlockSize;
        byte[] left = inputBlock[..halfSize];
        byte[] right = inputBlock[halfSize..];

        foreach (byte[] roundKey in roundKeys)
        {
            byte[] transformed = TransformHalf(right, roundKey);
            byte[] nextRight = Xor(left, transformed);
            left = right;
            right = nextRight;
        }

        return JoinHalves(left, right);
    }

    public byte[] DecryptBlock(byte[] inputBlock)
    {
        ArgumentNullException.ThrowIfNull(inputBlock);
        ValidateBlockSize(inputBlock);

        byte[][] roundKeys = _roundKeys
            ?? throw new InvalidOperationException(
                "The key has not been configured.");

        int halfSize = _transformation.InputBlockSize;
        byte[] left = inputBlock[..halfSize];
        byte[] right = inputBlock[halfSize..];

        for (int round = roundKeys.Length - 1; round >= 0; round--)
        {
            byte[] previousRight = left;
            byte[] transformed = TransformHalf(left, roundKeys[round]);
            byte[] previousLeft = Xor(right, transformed);
            left = previousLeft;
            right = previousRight;
        }

        return JoinHalves(left, right);
    }

    private byte[][] ExpandAndValidateKey(byte[] key)
    {
        byte[][]? roundKeys = _keyExpansion.ExpandKey(key.ToArray());

        if (roundKeys is null || roundKeys.Length == 0)
        {
            throw new InvalidOperationException(
                "Key expansion must produce at least one round key.");
        }

        byte[][] result = new byte[roundKeys.Length][];
        for (int round = 0; round < roundKeys.Length; round++)
        {
            if (roundKeys[round] is null || roundKeys[round].Length == 0)
            {
                throw new InvalidOperationException(
                    $"Round key {round} is null or empty.");
            }

            result[round] = roundKeys[round].ToArray();
        }

        return result;
    }

    private byte[] TransformHalf(byte[] halfBlock, byte[] roundKey)
    {
        byte[]? result = _transformation.Transform(
            halfBlock.ToArray(),
            roundKey.ToArray());

        if (result is null || result.Length != _transformation.InputBlockSize)
        {
            throw new InvalidOperationException(
                "The round transformation returned an invalid block size.");
        }

        return result;
    }

    private void ValidateBlockSize(byte[] block)
    {
        if (block.Length != BlockSize)
        {
            throw new ArgumentException(
                $"The input block must contain exactly {BlockSize} bytes.",
                nameof(block));
        }
    }

    private static byte[] Xor(byte[] left, byte[] right)
    {
        byte[] result = new byte[left.Length];
        for (int index = 0; index < result.Length; index++)
        {
            result[index] = (byte)(left[index] ^ right[index]);
        }

        return result;
    }

    private static byte[] JoinHalves(byte[] left, byte[] right)
    {
        byte[] result = new byte[left.Length + right.Length];
        Buffer.BlockCopy(left, 0, result, 0, left.Length);
        Buffer.BlockCopy(right, 0, result, left.Length, right.Length);
        return result;
    }
}
