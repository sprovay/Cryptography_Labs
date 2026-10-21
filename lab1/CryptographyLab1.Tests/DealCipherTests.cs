using CryptographyLab1;
using NUnit.Framework;

namespace CryptographyLab1.Tests;

[TestFixture]
public class DealCipherTests
{
    private static readonly CipherMode[] CipherModes =
        Enum.GetValues<CipherMode>();

    private static readonly byte[][] SupportedKeys =
    [
        Convert.FromHexString("00112233445566778899AABBCCDDEEFF"),
        Convert.FromHexString(
            "00112233445566778899AABBCCDDEEFF1021324354657687"),
        Convert.FromHexString(
            "00112233445566778899AABBCCDDEEFF" +
            "102132435465768798A9BACBDCEDFE0F")
    ];

    // Проверяет количество раундовых ключей для ключей DEAL длиной 128, 192 и 256 бит.
    [TestCase(16, 6)]
    [TestCase(24, 6)]
    [TestCase(32, 8)]
    public void KeyExpansion_ProducesRequiredRoundCount(
        int keyLength,
        int expectedRoundCount)
    {
        byte[][] roundKeys = new DealKeyExpansion().ExpandKey(
            new byte[keyLength]);

        Assert.Multiple(() =>
        {
            Assert.That(roundKeys, Has.Length.EqualTo(expectedRoundCount));
            Assert.That(roundKeys, Has.All.Length.EqualTo(8));
        });
    }

    // Проверяет все шесть шагов расписания DEAL-128, включая константы 1, 2, 4 и 8.
    [Test]
    public void KeyExpansion_Deal128FollowsSpecification()
    {
        byte[] key = SupportedKeys[0];
        byte[][] actual = new DealKeyExpansion().ExpandKey(key);
        var des = new DesCipher();
        des.SetKey(Convert.FromHexString("0123456789ABCDEF"));

        byte[][] expected = new byte[6][];
        expected[0] = des.EncryptBlock(key[..8]);
        expected[1] = des.EncryptBlock(Xor(key[8..16], expected[0]));
        expected[2] = des.EncryptBlock(
            Xor(key[..8], expected[1], Constant(1)));
        expected[3] = des.EncryptBlock(
            Xor(key[8..16], expected[2], Constant(2)));
        expected[4] = des.EncryptBlock(
            Xor(key[..8], expected[3], Constant(4)));
        expected[5] = des.EncryptBlock(
            Xor(key[8..16], expected[4], Constant(8)));

        Assert.That(actual, Is.EqualTo(expected));
    }

    // Проверяет, что адаптер возвращает тот же результат, что и прямое шифрование блока DES.
    [Test]
    public void DesAdapter_MatchesDirectDesEncryption()
    {
        byte[] roundKey = Convert.FromHexString("133457799BBCDFF1");
        byte[] input = Convert.FromHexString("0123456789ABCDEF");
        var directDes = new DesCipher();
        directDes.SetKey(roundKey);

        byte[] expected = directDes.EncryptBlock(input);
        byte[] actual = new DesRoundFunctionAdapter().Transform(input, roundKey);

        Assert.That(actual, Is.EqualTo(expected));
    }

    // Проверяет установленный спецификацией размер блока DEAL, равный 128 битам.
    [Test]
    public void BlockSize_IsSixteenBytes()
    {
        Assert.That(new DealCipher().BlockSize, Is.EqualTo(16));
    }

    // Проверяет обратимость DEAL для всех поддерживаемых размеров исходного ключа.
    [TestCaseSource(nameof(SupportedKeys))]
    public void EverySupportedKeySize_RoundTripRestoresBlock(byte[] key)
    {
        var deal = new DealCipher();
        deal.SetKey(key);
        byte[] source = Convert.FromHexString(
            "0123456789ABCDEFFEDCBA9876543210");

        byte[] encrypted = deal.EncryptBlock(source);
        byte[] decrypted = deal.DecryptBlock(encrypted);

        Assert.Multiple(() =>
        {
            Assert.That(encrypted, Is.Not.EqualTo(source));
            Assert.That(decrypted, Is.EqualTo(source));
        });
    }

    // Проверяет совместную работу DEAL, режима CBC, набивки PKCS7 и общего контекста.
    [Test]
    public async Task Deal_WorksInsideSymmetricCipherContext()
    {
        var context = new SymmetricCipherContext(
            new DealCipher(),
            SupportedKeys[0],
            CipherMode.Cbc,
            PaddingMode.Pkcs7,
            Convert.FromHexString("00112233445566778899AABBCCDDEEFF"));
        byte[] source = Convert.FromHexString(
            "00112233445566778899AABBCCDDEEFF1020304050");

        byte[] encrypted = await context.EncryptAsync(source);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        Assert.That(decrypted, Is.EqualTo(source));
    }

    // Проверяет шифрование и восстановление данных алгоритмом DEAL во всех режимах задания.
    [TestCaseSource(nameof(CipherModes))]
    public async Task EveryCipherMode_RoundTripRestoresData(CipherMode cipherMode)
    {
        object[] additionalParameters = cipherMode == CipherMode.RandomDelta
            ? [Convert.FromHexString("00000000000000000000000000000007")]
            : [];
        var context = new SymmetricCipherContext(
            new DealCipher(),
            SupportedKeys[0],
            cipherMode,
            PaddingMode.Pkcs7,
            Convert.FromHexString("00112233445566778899AABBCCDDEEFF"),
            additionalParameters);
        byte[] source = Convert.FromHexString(
            "102030405060708090A0B0C0D0E0F00102030405");

        byte[] encrypted = await context.EncryptAsync(source);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        Assert.That(decrypted, Is.EqualTo(source));
    }

    // Проверяет отклонение ключей, длина которых не предусмотрена спецификацией DEAL.
    [TestCase(0)]
    [TestCase(8)]
    [TestCase(20)]
    [TestCase(33)]
    public void IncorrectKeyLength_IsRejected(int keyLength)
    {
        Assert.Throws<ArgumentException>(() =>
            new DealKeyExpansion().ExpandKey(new byte[keyLength]));
    }

    // Проверяет отклонение блока, длина которого не равна шестнадцати байтам.
    [Test]
    public void IncorrectBlockLength_IsRejected()
    {
        var deal = new DealCipher();
        deal.SetKey(SupportedKeys[0]);

        Assert.Throws<ArgumentException>(() =>
            deal.EncryptBlock(new byte[8]));
    }

    private static byte[] Constant(byte value)
    {
        byte[] result = new byte[8];
        result[^1] = value;
        return result;
    }

    private static byte[] Xor(params byte[][] values)
    {
        byte[] result = new byte[values[0].Length];
        foreach (byte[] value in values)
        {
            for (int index = 0; index < result.Length; index++)
            {
                result[index] ^= value[index];
            }
        }

        return result;
    }
}
