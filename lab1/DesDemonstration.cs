namespace CryptographyLab1;
// dotnet run -- --des-demo
public static class DesDemonstration
{
    private static readonly byte[] Key =
        Convert.FromHexString("133457799BBCDFF1");

    private static readonly byte[] InitializationVector =
        Convert.FromHexString("1234567890ABCDEF");

    private static readonly byte[] RandomDelta =
        Convert.FromHexString("000000000000001D");

    public static async Task RunAsync(
        string inputDirectory,
        string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);

        if (!Directory.Exists(inputDirectory))
        {
            throw new DirectoryNotFoundException(
                $"Input directory was not found: {inputDirectory}");
        }

        Console.WriteLine("DES byte sequence demonstration");
        await DemonstrateByteSequencesAsync(cancellationToken);

        Console.WriteLine();
        Console.WriteLine($"DES input files: {Path.GetFullPath(inputDirectory)}");
        Console.WriteLine($"DES results:     {Path.GetFullPath(outputDirectory)}");
        await DemonstrateFilesAsync(
            inputDirectory,
            outputDirectory,
            cancellationToken);
    }

    private static async Task DemonstrateByteSequencesAsync(
        CancellationToken cancellationToken)
    {
        int[] lengths = [0, 1, 7, 8, 9, 31, 256];
        var random = new Random(2026);

        foreach (CipherMode cipherMode in Enum.GetValues<CipherMode>())
        {
            var context = CreateContext(cipherMode);

            foreach (int length in lengths)
            {
                byte[] source = new byte[length];
                random.NextBytes(source);

                byte[] encrypted = await context.EncryptAsync(
                    source,
                    cancellationToken);
                byte[] decrypted = await context.DecryptAsync(
                    encrypted,
                    cancellationToken);

                EnsureEqual(source, decrypted, $"{cipherMode}, {length} bytes");
            }

            Console.WriteLine(
                $"  [OK] {cipherMode,-11} lengths: {string.Join(", ", lengths)}");
        }
    }

    private static async Task DemonstrateFilesAsync(
        string inputDirectory,
        string outputDirectory,
        CancellationToken cancellationToken)
    {
        string encryptedDirectory = Path.Combine(outputDirectory, "encrypted");
        string decryptedDirectory = Path.Combine(outputDirectory, "decrypted");

        Directory.CreateDirectory(encryptedDirectory);
        Directory.CreateDirectory(decryptedDirectory);

        string[] inputFiles = Directory
            .GetFiles(inputDirectory, "*", SearchOption.TopDirectoryOnly)
            .OrderBy(
                path => Path.GetFileName(path),
                StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (inputFiles.Length == 0)
        {
            throw new InvalidOperationException(
                $"Input directory contains no files: {inputDirectory}");
        }

        CipherMode[] cipherModes = Enum.GetValues<CipherMode>();

        for (int index = 0; index < inputFiles.Length; index++)
        {
            CipherMode cipherMode = cipherModes[index % cipherModes.Length];
            await DemonstrateFileAsync(
                inputFiles[index],
                cipherMode,
                encryptedDirectory,
                decryptedDirectory,
                cancellationToken);
        }
    }

    private static async Task DemonstrateFileAsync(
        string inputPath,
        CipherMode cipherMode,
        string encryptedDirectory,
        string decryptedDirectory,
        CancellationToken cancellationToken)
    {
        string fileName = Path.GetFileName(inputPath);
        string encryptedPath = Path.Combine(
            encryptedDirectory,
            fileName + ".des");
        string decryptedPath = Path.Combine(decryptedDirectory, fileName);

        var context = CreateContext(cipherMode);
        await context.EncryptAsync(
            inputPath,
            encryptedPath,
            cancellationToken);
        await context.DecryptAsync(
            encryptedPath,
            decryptedPath,
            cancellationToken);

        byte[] original = await File.ReadAllBytesAsync(
            inputPath,
            cancellationToken);
        byte[] decrypted = await File.ReadAllBytesAsync(
            decryptedPath,
            cancellationToken);
        EnsureEqual(original, decrypted, fileName);

        Console.WriteLine(
            $"  [OK] {fileName,-28} {cipherMode,-11} " +
            $"{original.Length,10} bytes");
    }

    private static SymmetricCipherContext CreateContext(CipherMode cipherMode)
    {
        object[] additionalParameters = cipherMode == CipherMode.RandomDelta
            ? [RandomDelta]
            : [];

        return new SymmetricCipherContext(
            new DesCipher(),
            Key,
            cipherMode,
            PaddingMode.Pkcs7,
            InitializationVector,
            additionalParameters);
    }

    private static void EnsureEqual(
        byte[] expected,
        byte[] actual,
        string description)
    {
        if (!expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidOperationException(
                $"DES round-trip failed for {description}.");
        }
    }
}
