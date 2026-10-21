namespace CryptographyLab1;

public enum BitIndexingOrder
{
    LeastSignificantFirst,
    MostSignificantFirst
}


public static class BitPermutation
{
    public static byte[] Permute(
        byte[] value,
        int[] permutation,
        BitIndexingOrder indexingOrder,
        int firstBitNumber)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(permutation);

        if (firstBitNumber is not (0 or 1))
        {
            throw new ArgumentOutOfRangeException(
                nameof(firstBitNumber),
                "The first bit number must be 0 or 1.");
        }

        if (!Enum.IsDefined(indexingOrder))
        {
            throw new ArgumentOutOfRangeException(
                nameof(indexingOrder),
                "Unknown bit indexing order.");
        }

        int inputBitCount = checked(value.Length * 8);
        byte[] result = new byte[(permutation.Length + 7) / 8];

        for (int outputIndex = 0; outputIndex < permutation.Length; outputIndex++)
        {
            int inputIndex = permutation[outputIndex] - firstBitNumber;

            if (inputIndex < 0 || inputIndex >= inputBitCount)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(permutation),
                    $"Bit number {permutation[outputIndex]} at position " +
                    $"{outputIndex} is outside the input value.");
            }

            int bit = GetBit(value, inputIndex, indexingOrder);
            SetBit(result, outputIndex, bit, indexingOrder);
        }

        return result;
    }

    private static int GetBit(
        byte[] bytes,
        int zeroBasedIndex,
        BitIndexingOrder indexingOrder)
    {
        int byteOffset = zeroBasedIndex / 8;
        int bitIndexInsideByte = zeroBasedIndex % 8;
        int byteIndex;
        int shift;

        if (indexingOrder == BitIndexingOrder.MostSignificantFirst)
        {
            byteIndex = byteOffset;
            shift = 7 - bitIndexInsideByte;
        }
        else
        {
            byteIndex = bytes.Length - 1 - byteOffset;
            shift = bitIndexInsideByte;
        }

        return (bytes[byteIndex] >> shift) & 1;
    }

    private static void SetBit(
        byte[] bytes,
        int zeroBasedIndex,
        int value,
        BitIndexingOrder indexingOrder)
    {
        if (value == 0)
        {
            return;
        }

        int byteOffset = zeroBasedIndex / 8;
        int bitIndexInsideByte = zeroBasedIndex % 8;
        int byteIndex;
        int shift;

        if (indexingOrder == BitIndexingOrder.MostSignificantFirst)
        {
            byteIndex = byteOffset;
            shift = 7 - bitIndexInsideByte;
        }
        else
        {
            byteIndex = bytes.Length - 1 - byteOffset;
            shift = bitIndexInsideByte;
        }

        bytes[byteIndex] |= (byte)(1 << shift);
    }
}
