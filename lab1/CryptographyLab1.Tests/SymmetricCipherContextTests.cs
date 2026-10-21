using CryptographyLab1;
using NUnit.Framework;

namespace CryptographyLab1.Tests;

[TestFixture]
public class SymmetricCipherContextTests
{
    private static readonly CipherMode[] CipherModes =
        Enum.GetValues<CipherMode>();

    private static readonly PaddingMode[] PaddingModes =
        Enum.GetValues<PaddingMode>();

    // Проверяет восстановление данных для каждой комбинации режима шифрования и набивки.
    [Test]
    public async Task EveryModeAndPadding_RoundTripRestoresOriginalData(
        [ValueSource(nameof(CipherModes))] CipherMode cipherMode,
        [ValueSource(nameof(PaddingModes))] PaddingMode paddingMode)
    {
        byte[] source = [0x10, 0x20, 0x30, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95];
        var context = CreateContext(cipherMode, paddingMode);

        byte[] encrypted = await context.EncryptAsync(source);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        Assert.That(decrypted, Is.EqualTo(source));
    }

    // Проверяет асинхронное шифрование файла и полное восстановление его содержимого.
    [Test]
    public async Task FileOverloads_RoundTripRestoresOriginalFile()
    {
        string inputPath = Path.GetTempFileName();
        string encryptedPath = Path.GetTempFileName();
        string outputPath = Path.GetTempFileName();

        try
        {
            byte[] source = [1, 2, 3, 4, 5, 6, 7];
            await File.WriteAllBytesAsync(inputPath, source);
            var context = CreateContext(CipherMode.Cbc, PaddingMode.Pkcs7);

            await context.EncryptAsync(inputPath, encryptedPath);
            await context.DecryptAsync(encryptedPath, outputPath);

            Assert.That(
                await File.ReadAllBytesAsync(outputPath),
                Is.EqualTo(source));
        }
        finally
        {
            File.Delete(inputPath);
            File.Delete(encryptedPath);
            File.Delete(outputPath);
        }
    }

    // Проверяет, что Random Delta нельзя создать без обязательного массива Delta.
    [Test]
    public void RandomDelta_WithoutDeltaParameter_IsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipherContext(
                new XorBlockCipher(4),
                [0xA5, 0x3C, 0x7F, 0x11],
                CipherMode.RandomDelta,
                PaddingMode.Pkcs7,
                [1, 2, 3, 4]));
    }

    // Проверяет формулу Random Delta: при Delta = 1 результат должен совпасть с CTR.
    [Test]
    public async Task RandomDelta_WithDeltaOne_MatchesCtr()
    {
        byte[] key = Convert.FromHexString("133457799BBCDFF1");
        byte[] initializationVector = Convert.FromHexString("1234567890ABCDEF");
        byte[] deltaOne = Convert.FromHexString("0000000000000001");
        byte[] source = Convert.FromHexString(
            "00112233445566778899AABBCCDDEEFF1020304050");

        var ctr = new SymmetricCipherContext(
            new DesCipher(),
            key,
            CipherMode.Ctr,
            PaddingMode.Pkcs7,
            initializationVector);
        var randomDelta = new SymmetricCipherContext(
            new DesCipher(),
            key,
            CipherMode.RandomDelta,
            PaddingMode.Pkcs7,
            initializationVector,
            deltaOne);

        byte[] ctrResult = await ctr.EncryptAsync(source);
        byte[] randomDeltaResult = await randomDelta.EncryptAsync(source);

        Assert.That(randomDeltaResult, Is.EqualTo(ctrResult));
    }

    private static SymmetricCipherContext CreateContext(
        CipherMode cipherMode,
        PaddingMode paddingMode)
    {
        object[] additionalParameters = cipherMode == CipherMode.RandomDelta
            ? [new byte[] { 0, 0, 0, 7 }]
            : [];

        return new SymmetricCipherContext(
            new XorBlockCipher(4),
            [0xA5, 0x3C, 0x7F, 0x11],
            cipherMode,
            paddingMode,
            [0x12, 0x34, 0x56, 0x78],
            additionalParameters);
    }

    private sealed class XorBlockCipher(int blockSize) : ISymmetricCipher
    {
        private byte[] _key = [];

        public int BlockSize { get; } = blockSize;

        public void SetKey(byte[] key)
        {
            _key = key.ToArray();
        }

        public byte[] EncryptBlock(byte[] inputBlock) =>
            Transform(inputBlock, _key);

        public byte[] DecryptBlock(byte[] inputBlock) =>
            Transform(inputBlock, _key);

        private byte[] Transform(byte[] inputBlock, byte[] key)
        {
            if (inputBlock.Length != BlockSize)
            {
                throw new ArgumentException("Invalid block size.");
            }

            byte[] result = new byte[BlockSize];
            for (int index = 0; index < result.Length; index++)
            {
                result[index] = (byte)(inputBlock[index] ^ key[index % key.Length]);
            }

            return result;
        }
    }
}
