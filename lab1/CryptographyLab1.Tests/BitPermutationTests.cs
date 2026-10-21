using CryptographyLab1;
using NUnit.Framework;

namespace CryptographyLab1.Tests;

[TestFixture]
public class BitPermutationTests
{
    // Проверяет, что при порядке от старшего бита индекс 0 указывает на левый бит байта.
    [Test]
    public void OneByte_MostSignificantFirst_UsesLeftmostBitAsIndexZero()
    {
        byte[] result = BitPermutation.Permute(
            [0b1000_0000],
            [0],
            BitIndexingOrder.MostSignificantFirst,
            firstBitNumber: 0);

        Assert.That(result, Is.EqualTo(new byte[] { 0b1000_0000 }));
    }

    // Проверяет, что при порядке от младшего бита индекс 0 указывает на правый бит байта.
    [Test]
    public void OneByte_LeastSignificantFirst_UsesRightmostBitAsIndexZero()
    {
        byte[] result = BitPermutation.Permute(
            [0b0000_0001],
            [0],
            BitIndexingOrder.LeastSignificantFirst,
            firstBitNumber: 0);

        Assert.That(result, Is.EqualTo(new byte[] { 0b0000_0001 }));
    }

    // Проверяет глобальную MSB-нумерацию: индексы проходят от первого байта к последнему.
    [Test]
    public void TwoBytes_MostSignificantFirst_IndexesFromFirstByteToLastByte()
    {
        byte[] result = BitPermutation.Permute(
            [0b1000_0000, 0b0000_0001],
            [0, 15],
            BitIndexingOrder.MostSignificantFirst,
            firstBitNumber: 0);

        Assert.That(result, Is.EqualTo(new byte[] { 0b1100_0000 }));
    }

    // Проверяет глобальную LSB-нумерацию: индекс 0 берётся из младшего бита последнего байта.
    [Test]
    public void TwoBytes_LeastSignificantFirst_IndexZeroUsesLastByte()
    {
        byte[] result = BitPermutation.Permute(
            [0b0000_0000, 0b0000_0001],
            [0],
            BitIndexingOrder.LeastSignificantFirst,
            firstBitNumber: 0);

        Assert.That(result, Is.EqualTo(new byte[] { 0b0000_0001 }));
    }

    // Проверяет, что тождественный P-блок сохраняет многобайтовое значение в обоих порядках.
    [TestCase(BitIndexingOrder.MostSignificantFirst)]
    [TestCase(BitIndexingOrder.LeastSignificantFirst)]
    public void IdentityPermutation_PreservesValue(BitIndexingOrder indexingOrder)
    {
        byte[] source = [0x12, 0x34, 0x56, 0x78];
        int[] identity = Enumerable.Range(0, source.Length * 8).ToArray();

        byte[] result = BitPermutation.Permute(
            source,
            identity,
            indexingOrder,
            firstBitNumber: 0);

        Assert.That(result, Is.EqualTo(source));
    }

    // Проверяет полный разворот битов через границу байтов для обоих порядков нумерации.
    [TestCase(BitIndexingOrder.MostSignificantFirst)]
    [TestCase(BitIndexingOrder.LeastSignificantFirst)]
    public void FullReversal_ReversesAllBitsAcrossByteBoundary(
        BitIndexingOrder indexingOrder)
    {
        byte[] source = [0x12, 0x34];
        int[] reverse = Enumerable.Range(0, 16).Reverse().ToArray();

        byte[] result = BitPermutation.Permute(
            source,
            reverse,
            indexingOrder,
            firstBitNumber: 0);

        Assert.That(result, Is.EqualTo(new byte[] { 0x2C, 0x48 }));
    }

    // Проверяет правильное чтение номеров P-блока, когда нумерация начинается с нуля.
    [Test]
    public void FirstBitNumberZero_UsesZeroBasedPBlockNumbers()
    {
        byte[] result = BitPermutation.Permute(
            [0b1000_0000],
            [0, 7],
            BitIndexingOrder.MostSignificantFirst,
            firstBitNumber: 0);

        Assert.That(result, Is.EqualTo(new byte[] { 0b1000_0000 }));
    }

    // Проверяет преобразование номеров P-блока во внутренние индексы при нумерации с единицы.
    [Test]
    public void FirstBitNumberOne_UsesOneBasedPBlockNumbers()
    {
        byte[] result = BitPermutation.Permute(
            [0b1000_0000],
            [1, 8],
            BitIndexingOrder.MostSignificantFirst,
            firstBitNumber: 1);

        Assert.That(result, Is.EqualTo(new byte[] { 0b1000_0000 }));
    }

    // Проверяет выброс исключения, если P-блок ссылается на несуществующий входной бит.
    [Test]
    public void PBlockIndexOutsideInput_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            BitPermutation.Permute(
                [0x00, 0x00],
                [16],
                BitIndexingOrder.MostSignificantFirst,
                firstBitNumber: 0));
    }
}
