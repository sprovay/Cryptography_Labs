using CryptographyLab1;
using NUnit.Framework;

namespace CryptographyLab1.Tests;

[TestFixture]
public class DesCipherTests
{
    private static readonly byte[] Key =
        Convert.FromHexString("133457799BBCDFF1");

    // Проверяет расписание ключей DES по известным значениям первого и последнего раундов.
    [Test]
    public void KeyExpansion_ProducesKnownFirstAndLastRoundKeys()
    {
        byte[][] roundKeys = new DesKeyExpansion().ExpandKey(Key);

        Assert.Multiple(() =>
        {
            Assert.That(roundKeys, Has.Length.EqualTo(16));
            Assert.That(
                roundKeys[0],
                Is.EqualTo(Convert.FromHexString("1B02EFFC7072")));
            Assert.That(
                roundKeys[15],
                Is.EqualTo(Convert.FromHexString("CB3D8B0E17F5")));
        });
    }

    // Проверяет функцию F первого раунда DES по известному контрольному результату.
    [Test]
    public void RoundTransformation_ProducesKnownFirstRoundResult()
    {
        byte[] result = new DesRoundTransformation().Transform(
            Convert.FromHexString("F0AAF0AA"),
            Convert.FromHexString("1B02EFFC7072"));

        Assert.That(
            result,
            Is.EqualTo(Convert.FromHexString("234AA9BB")));
    }

    // Проверяет шифрование стандартного блока DES по известному тестовому вектору.
    [Test]
    public void EncryptBlock_ProducesKnownDesCiphertext()
    {
        var des = CreateConfiguredDes();

        byte[] encrypted = des.EncryptBlock(
            Convert.FromHexString("0123456789ABCDEF"));

        Assert.That(
            encrypted,
            Is.EqualTo(Convert.FromHexString("85E813540F0AB405")));
    }

    // Проверяет, что расшифрование известного шифротекста восстанавливает открытый текст.
    [Test]
    public void DecryptBlock_RestoresKnownPlaintext()
    {
        var des = CreateConfiguredDes();

        byte[] decrypted = des.DecryptBlock(
            Convert.FromHexString("85E813540F0AB405"));

        Assert.That(
            decrypted,
            Is.EqualTo(Convert.FromHexString("0123456789ABCDEF")));
    }

    // Проверяет совместную работу DES, режима CBC, набивки PKCS7 и асинхронного контекста.
    [Test]
    public async Task Des_WorksInsideSymmetricCipherContext()
    {
        var context = new SymmetricCipherContext(
            new DesCipher(),
            Key,
            CipherMode.Cbc,
            PaddingMode.Pkcs7,
            Convert.FromHexString("0102030405060708"));
        byte[] source = Convert.FromHexString("00112233445566778899AABBCC");

        byte[] encrypted = await context.EncryptAsync(source);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        Assert.That(decrypted, Is.EqualTo(source));
    }

    // Проверяет отклонение ключа DES, длина которого не равна восьми байтам.
    [Test]
    public void IncorrectKeyLength_IsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            new DesKeyExpansion().ExpandKey(new byte[7]));
    }

    private static DesCipher CreateConfiguredDes()
    {
        var des = new DesCipher();
        des.SetKey(Key);
        return des;
    }
}
