namespace CryptographyLab1;

public sealed class DesKeyExpansion : IKeyExpansion
{
    private static readonly int[] PermutedChoice1 =
    [
        57, 49, 41, 33, 25, 17, 9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
    ];

    private static readonly int[] PermutedChoice2 =
    [
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ];

    private static readonly int[] LeftShifts =
        [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    public byte[][] ExpandKey(byte[] inputKey)
    {
        ArgumentNullException.ThrowIfNull(inputKey);

        if (inputKey.Length != 8)
        {
            throw new ArgumentException(
                "A DES key must contain exactly 8 bytes, including parity bits.",
                nameof(inputKey));
        }

        byte[] permutedKey = BitPermutation.Permute(
            inputKey,
            PermutedChoice1,
            BitIndexingOrder.MostSignificantFirst,
            firstBitNumber: 1);

        bool[] left = ReadBits(permutedKey, startIndex: 0, count: 28);
        bool[] right = ReadBits(permutedKey, startIndex: 28, count: 28);
        byte[][] roundKeys = new byte[LeftShifts.Length][];

        for (int round = 0; round < roundKeys.Length; round++)
        {
            RotateLeft(left, LeftShifts[round]);
            RotateLeft(right, LeftShifts[round]);

            byte[] combinedHalves = new byte[7];
            WriteBits(combinedHalves, left, destinationIndex: 0);
            WriteBits(combinedHalves, right, destinationIndex: 28);

            roundKeys[round] = BitPermutation.Permute(
                combinedHalves,
                PermutedChoice2,
                BitIndexingOrder.MostSignificantFirst,
                firstBitNumber: 1);
        }

        return roundKeys;
    }

    private static bool[] ReadBits(byte[] source, int startIndex, int count)
    {
        bool[] result = new bool[count];
        for (int index = 0; index < count; index++)
        {
            result[index] = GetBit(source, startIndex + index) != 0;
        }

        return result;
    }

    private static void WriteBits(
        byte[] destination,
        bool[] bits,
        int destinationIndex)
    {
        for (int index = 0; index < bits.Length; index++)
        {
            if (bits[index])
            {
                SetBit(destination, destinationIndex + index);
            }
        }
    }

    private static void RotateLeft(bool[] bits, int count)
    {
        for (int rotation = 0; rotation < count; rotation++)
        {
            bool first = bits[0];
            for (int index = 0; index < bits.Length - 1; index++)
            {
                bits[index] = bits[index + 1];
            }

            bits[^1] = first;
        }
    }

    private static int GetBit(byte[] bytes, int index) =>
        (bytes[index / 8] >> (7 - index % 8)) & 1;

    private static void SetBit(byte[] bytes, int index) =>
        bytes[index / 8] |= (byte)(1 << (7 - index % 8));
}

public sealed class DesRoundTransformation : IEncryptionTransformation
{
    private static readonly int[] ExpansionPermutation =
    [
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
    ];

    private static readonly int[] StraightPermutation =
    [
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
    ];

    private static readonly byte[][] SBoxes =
    [
        [
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
             0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
             4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
        ],
        [
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
             3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
             0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
        ],
        [
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
             1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
        ],
        [
             7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
             3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
        ],
        [
             2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
             4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
        ],
        [
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
             9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
             4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
        ],
        [
             4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
             1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
             6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
        ],
        [
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
             1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
             7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
             2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
        ]
    ];

    public int InputBlockSize => 4;

    public byte[] Transform(byte[] inputBlock, byte[] roundKey)
    {
        ArgumentNullException.ThrowIfNull(inputBlock);
        ArgumentNullException.ThrowIfNull(roundKey);

        if (inputBlock.Length != InputBlockSize)
        {
            throw new ArgumentException(
                "The DES round input must contain exactly 4 bytes.",
                nameof(inputBlock));
        }

        if (roundKey.Length != 6)
        {
            throw new ArgumentException(
                "A DES round key must contain exactly 6 bytes.",
                nameof(roundKey));
        }

        byte[] expanded = BitPermutation.Permute(
            inputBlock,
            ExpansionPermutation,
            BitIndexingOrder.MostSignificantFirst,
            firstBitNumber: 1);

        for (int index = 0; index < expanded.Length; index++)
        {
            expanded[index] ^= roundKey[index];
        }

        byte[] substituted = ApplySBoxes(expanded);
        return BitPermutation.Permute(
            substituted,
            StraightPermutation,
            BitIndexingOrder.MostSignificantFirst,
            firstBitNumber: 1);
    }

    private static byte[] ApplySBoxes(byte[] input)
    {
        byte[] result = new byte[4];

        for (int box = 0; box < SBoxes.Length; box++)
        {
            int inputOffset = box * 6;
            int row = GetBit(input, inputOffset) * 2
                + GetBit(input, inputOffset + 5);
            int column = GetBit(input, inputOffset + 1) * 8
                + GetBit(input, inputOffset + 2) * 4
                + GetBit(input, inputOffset + 3) * 2
                + GetBit(input, inputOffset + 4);
            int value = SBoxes[box][row * 16 + column];

            for (int bit = 0; bit < 4; bit++)
            {
                if ((value & (1 << (3 - bit))) != 0)
                {
                    SetBit(result, box * 4 + bit);
                }
            }
        }

        return result;
    }

    private static int GetBit(byte[] bytes, int index) =>
        (bytes[index / 8] >> (7 - index % 8)) & 1;

    private static void SetBit(byte[] bytes, int index) =>
        bytes[index / 8] |= (byte)(1 << (7 - index % 8));
}

public sealed class DesCipher : ISymmetricCipher
{
    private static readonly int[] InitialPermutation =
    [
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7
    ];

    private static readonly int[] FinalPermutation =
    [
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
    ];

    private readonly FeistelNetwork _network = new(
        new DesKeyExpansion(),
        new DesRoundTransformation());

    public int BlockSize => 8;

    public void SetKey(byte[] key) =>
        _network.SetKey(key);

    public byte[] EncryptBlock(byte[] inputBlock)
    {
        ValidateBlock(inputBlock);
        byte[] permuted = ApplyPermutation(inputBlock, InitialPermutation);
        byte[] afterRounds = _network.EncryptBlock(permuted);
        return ApplyPermutation(SwapHalves(afterRounds), FinalPermutation);
    }

    public byte[] DecryptBlock(byte[] inputBlock)
    {
        ValidateBlock(inputBlock);
        byte[] permuted = ApplyPermutation(inputBlock, InitialPermutation);
        byte[] afterRounds = _network.DecryptBlock(SwapHalves(permuted));
        return ApplyPermutation(afterRounds, FinalPermutation);
    }

    private static byte[] ApplyPermutation(byte[] value, int[] rule) =>
        BitPermutation.Permute(
            value,
            rule,
            BitIndexingOrder.MostSignificantFirst,
            firstBitNumber: 1);

    private static byte[] SwapHalves(byte[] block)
    {
        byte[] result = new byte[block.Length];
        int halfSize = block.Length / 2;
        Buffer.BlockCopy(block, halfSize, result, 0, halfSize);
        Buffer.BlockCopy(block, 0, result, halfSize, halfSize);
        return result;
    }

    private static void ValidateBlock(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);

        if (block.Length != 8)
        {
            throw new ArgumentException(
                "A DES block must contain exactly 8 bytes.",
                nameof(block));
        }
    }
}
