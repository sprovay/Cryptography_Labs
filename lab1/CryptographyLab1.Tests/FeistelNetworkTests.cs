using CryptographyLab1;
using NUnit.Framework;

namespace CryptographyLab1.Tests;

[TestFixture]
public class FeistelNetworkTests
{
    // Проверяет обратимость сети: дешифрование результата возвращает исходный блок.
    [Test]
    public void EncryptThenDecrypt_RestoresOriginalBlock()
    {
        var network = CreateConfiguredNetwork();
        byte[] source = [0x12, 0x34, 0x56, 0x78];

        byte[] encrypted = network.EncryptBlock(source);
        byte[] decrypted = network.DecryptBlock(encrypted);

        Assert.Multiple(() =>
        {
            Assert.That(encrypted, Is.Not.EqualTo(source));
            Assert.That(decrypted, Is.EqualTo(source));
        });
    }

    // Проверяет, что полный блок сети вдвое больше входа раундового преобразования.
    [Test]
    public void BlockSize_IsTwiceTransformationInputSize()
    {
        var network = new FeistelNetwork(
            new TestKeyExpansion(),
            new TestTransformation(halfBlockSize: 3));

        Assert.That(network.BlockSize, Is.EqualTo(6));
    }

    // Проверяет запрет шифрования до настройки исходного и раундовых ключей.
    [Test]
    public void EncryptBlock_WithoutConfiguredKey_IsRejected()
    {
        var network = new FeistelNetwork(
            new TestKeyExpansion(),
            new TestTransformation(halfBlockSize: 2));

        Assert.Throws<InvalidOperationException>(() =>
            network.EncryptBlock([1, 2, 3, 4]));
    }

    // Проверяет отклонение входного блока, длина которого не равна BlockSize сети.
    [Test]
    public void IncorrectInputBlockSize_IsRejected()
    {
        var network = CreateConfiguredNetwork();

        Assert.Throws<ArgumentException>(() =>
            network.EncryptBlock([1, 2, 3]));
    }

    // Проверяет, что универсальная сеть Фейстеля работает через SymmetricCipherContext.
    [Test]
    public async Task FeistelNetwork_WorksInsideSymmetricCipherContext()
    {
        var network = new FeistelNetwork(
            new TestKeyExpansion(),
            new TestTransformation(halfBlockSize: 2));
        var context = new SymmetricCipherContext(
            network,
            [0xA1, 0xB2, 0xC3, 0xD4],
            CipherMode.Cbc,
            PaddingMode.Pkcs7,
            [0x10, 0x20, 0x30, 0x40]);
        byte[] source = [1, 2, 3, 4, 5, 6, 7];

        byte[] encrypted = await context.EncryptAsync(source);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        Assert.That(decrypted, Is.EqualTo(source));
    }

    private static FeistelNetwork CreateConfiguredNetwork()
    {
        var network = new FeistelNetwork(
            new TestKeyExpansion(),
            new TestTransformation(halfBlockSize: 2));
        byte[] key = [0xA1, 0xB2, 0xC3, 0xD4];
        network.SetKey(key);
        return network;
    }

    private sealed class TestKeyExpansion : IKeyExpansion
    {
        public byte[][] ExpandKey(byte[] inputKey) =>
        [
            [inputKey[0], inputKey[1]],
            [inputKey[2], inputKey[3]],
            [(byte)(inputKey[0] ^ inputKey[2]),
             (byte)(inputKey[1] ^ inputKey[3])]
        ];
    }

    private sealed class TestTransformation(int halfBlockSize)
        : IEncryptionTransformation
    {
        public int InputBlockSize { get; } = halfBlockSize;

        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            byte[] result = new byte[InputBlockSize];
            for (int index = 0; index < result.Length; index++)
            {
                byte value = inputBlock[index];
                byte key = roundKey[index % roundKey.Length];
                result[index] = (byte)((value + key) ^ (value >> 3));
            }

            return result;
        }
    }
}
