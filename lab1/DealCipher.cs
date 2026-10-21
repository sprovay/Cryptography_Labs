using System.Buffers.Binary;
using System.Collections.Concurrent;

namespace CryptographyLab1;

public sealed class DealKeyExpansion : IKeyExpansion
{
    private static readonly byte[] KeyScheduleEncryptionKey =
        Convert.FromHexString("0123456789ABCDEF");

    public byte[][] ExpandKey(byte[] inputKey)
    {
        ArgumentNullException.ThrowIfNull(inputKey);

        int keyPartCount = inputKey.Length switch
        {
            16 => 2,
            24 => 3,
            32 => 4,
            _ => throw new ArgumentException(
                "A DEAL key must contain 16, 24, or 32 bytes.",
                nameof(inputKey))
        };

        int roundCount = inputKey.Length == 32 ? 8 : 6;
        byte[][] keyParts = SplitKey(inputKey, keyPartCount);
        byte[][] roundKeys = new byte[roundCount][];

        var des = new DesCipher();
        des.SetKey(KeyScheduleEncryptionKey);

        for (int round = 0; round < roundCount; round++)
        {
            byte[] scheduleInput = keyParts[round % keyPartCount].ToArray();

            if (round > 0)
            {
                XorInto(scheduleInput, roundKeys[round - 1]);
            }

            if (round >= keyPartCount)
            {
                int constant = 1 << (round - keyPartCount);
                scheduleInput[^1] ^= checked((byte)constant);
            }

            roundKeys[round] = des.EncryptBlock(scheduleInput);
        }

        return roundKeys;
    }

    private static byte[][] SplitKey(byte[] key, int partCount)
    {
        byte[][] result = new byte[partCount][];
        for (int part = 0; part < partCount; part++)
        {
            result[part] = key[(part * 8)..((part + 1) * 8)];
        }

        return result;
    }

    private static void XorInto(byte[] target, byte[] value)
    {
        for (int index = 0; index < target.Length; index++)
        {
            target[index] ^= value[index];
        }
    }
}

public sealed class DesRoundFunctionAdapter : IEncryptionTransformation
{
    private readonly ConcurrentDictionary<ulong, DesCipher> _ciphers = new();

    public int InputBlockSize => 8;

    public byte[] Transform(byte[] inputBlock, byte[] roundKey)
    {
        ArgumentNullException.ThrowIfNull(inputBlock);
        ArgumentNullException.ThrowIfNull(roundKey);

        if (inputBlock.Length != InputBlockSize)
        {
            throw new ArgumentException(
                "A DEAL half-block must contain exactly 8 bytes.",
                nameof(inputBlock));
        }

        if (roundKey.Length != 8)
        {
            throw new ArgumentException(
                "A DEAL round key must contain exactly 8 bytes.",
                nameof(roundKey));
        }

        ulong keyValue = BinaryPrimitives.ReadUInt64BigEndian(roundKey);
        DesCipher des = _ciphers.GetOrAdd(keyValue, CreateDesCipher);
        return des.EncryptBlock(inputBlock);
    }

    private static DesCipher CreateDesCipher(ulong keyValue)
    {
        byte[] key = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(key, keyValue);

        var des = new DesCipher();
        des.SetKey(key);
        return des;
    }
}

public sealed class DealCipher : ISymmetricCipher
{
    private readonly FeistelNetwork _network = new(
        new DealKeyExpansion(),
        new DesRoundFunctionAdapter());

    public int BlockSize => _network.BlockSize;

    public void SetKey(byte[] key) => _network.SetKey(key);

    public byte[] EncryptBlock(byte[] inputBlock) =>
        _network.EncryptBlock(inputBlock);

    public byte[] DecryptBlock(byte[] inputBlock) =>
        _network.DecryptBlock(inputBlock);
}
