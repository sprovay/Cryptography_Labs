namespace CryptographyLab1;

public sealed class SymmetricCipherContext
{
    private readonly ISymmetricCipher _cipher;
    private readonly CipherMode _cipherMode;
    private readonly PaddingMode _paddingMode;
    private readonly byte[]? _initializationVector;
    private readonly object[] _additionalParameters;

    public SymmetricCipherContext(
        ISymmetricCipher cipher,
        byte[] key,
        CipherMode cipherMode,
        PaddingMode paddingMode,
        byte[]? initializationVector = null,
        params object[] additionalParameters)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(additionalParameters);

        if (cipher.BlockSize <= 0)
        {
            throw new ArgumentException(
                "The cipher block size must be positive.",
                nameof(cipher));
        }

        if (!Enum.IsDefined(cipherMode))
        {
            throw new ArgumentOutOfRangeException(nameof(cipherMode));
        }

        if (!Enum.IsDefined(paddingMode))
        {
            throw new ArgumentOutOfRangeException(nameof(paddingMode));
        }

        if (paddingMode != PaddingMode.Zeros && cipher.BlockSize > byte.MaxValue)
        {
            throw new ArgumentException(
                "The selected padding mode supports blocks up to 255 bytes.",
                nameof(cipher));
        }

        bool requiresInitializationVector = cipherMode != CipherMode.Ecb;
        if (requiresInitializationVector && initializationVector is null)
        {
            throw new ArgumentNullException(
                nameof(initializationVector),
                $"Mode {cipherMode} requires an initialization vector.");
        }

        if (initializationVector is not null &&
            initializationVector.Length != cipher.BlockSize)
        {
            throw new ArgumentException(
                "The initialization vector length must equal the block size.",
                nameof(initializationVector));
        }

        _cipher = cipher;
        _cipherMode = cipherMode;
        _paddingMode = paddingMode;
        _initializationVector = initializationVector?.ToArray();
        _additionalParameters = CloneParameters(additionalParameters);

        ValidateModeParameters();

        _cipher.SetKey(key.ToArray());
    }

    public Task<byte[]> EncryptAsync(
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        byte[] input = data.ToArray();

        return Task.Run(
            () => EncryptCore(input, cancellationToken),
            cancellationToken);
    }

    public Task<byte[]> DecryptAsync(
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        byte[] input = data.ToArray();

        return Task.Run(
            () => DecryptCore(input, cancellationToken),
            cancellationToken);
    }

    public async Task EncryptAsync(
        string inputFilePath,
        string outputFilePath,
        CancellationToken cancellationToken = default)
    {
        ValidateFilePaths(inputFilePath, outputFilePath);
        byte[] input = await File.ReadAllBytesAsync(
            inputFilePath,
            cancellationToken);
        byte[] output = await EncryptAsync(input, cancellationToken);
        await File.WriteAllBytesAsync(
            outputFilePath,
            output,
            cancellationToken);
    }

    public async Task DecryptAsync(
        string inputFilePath,
        string outputFilePath,
        CancellationToken cancellationToken = default)
    {
        ValidateFilePaths(inputFilePath, outputFilePath);
        byte[] input = await File.ReadAllBytesAsync(
            inputFilePath,
            cancellationToken);
        byte[] output = await DecryptAsync(input, cancellationToken);
        await File.WriteAllBytesAsync(
            outputFilePath,
            output,
            cancellationToken);
    }

    private byte[] EncryptCore(
        byte[] data,
        CancellationToken cancellationToken)
    {
        byte[] paddedData = ApplyPadding(data);
        return ProcessBlocks(paddedData, encrypting: true, cancellationToken);
    }

    private byte[] DecryptCore(
        byte[] data,
        CancellationToken cancellationToken)
    {
        if (data.Length % _cipher.BlockSize != 0)
        {
            throw new ArgumentException(
                "Encrypted data length must be a multiple of the block size.",
                nameof(data));
        }

        if (data.Length == 0 && _paddingMode != PaddingMode.Zeros)
        {
            throw new ArgumentException(
                "Encrypted data cannot be empty for the selected padding mode.",
                nameof(data));
        }

        byte[] paddedResult = ProcessBlocks(
            data,
            encrypting: false,
            cancellationToken);
        return RemovePadding(paddedResult);
    }

    private byte[] ProcessBlocks(
        byte[] data,
        bool encrypting,
        CancellationToken cancellationToken)
    {
        if (data.Length == 0)
        {
            return [];
        }

        return _cipherMode switch
        {
            CipherMode.Ecb => ProcessEcb(data, encrypting, cancellationToken),
            CipherMode.Cbc => ProcessCbc(data, encrypting, cancellationToken),
            CipherMode.Pcbc => ProcessPcbc(data, encrypting, cancellationToken),
            CipherMode.Cfb => ProcessCfb(data, encrypting, cancellationToken),
            CipherMode.Ofb => ProcessOfb(data, cancellationToken),
            CipherMode.Ctr => ProcessCtr(data, cancellationToken),
            CipherMode.RandomDelta => ProcessRandomDelta(data, cancellationToken),
            _ => throw new InvalidOperationException("Unknown cipher mode.")
        };
    }

    private byte[] ProcessEcb(
        byte[] data,
        bool encrypting,
        CancellationToken cancellationToken)
    {
        byte[] result = new byte[data.Length];
        int blockCount = data.Length / _cipher.BlockSize;

        Parallel.For(
            0,
            blockCount,
            new ParallelOptions { CancellationToken = cancellationToken },
            blockIndex =>
            {
                byte[] inputBlock = GetBlock(data, blockIndex);
                byte[] outputBlock = encrypting
                    ? EncryptBlock(inputBlock)
                    : DecryptBlock(inputBlock);
                PutBlock(result, blockIndex, outputBlock);
            });

        return result;
    }

    private byte[] ProcessCbc(
        byte[] data,
        bool encrypting,
        CancellationToken cancellationToken)
    {
        byte[] result = new byte[data.Length];
        int blockCount = data.Length / _cipher.BlockSize;

        if (encrypting)
        {
            byte[] previousBlock = GetInitializationVector();
            for (int blockIndex = 0; blockIndex < blockCount; blockIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                byte[] inputBlock = GetBlock(data, blockIndex);
                byte[] outputBlock = EncryptBlock(Xor(inputBlock, previousBlock));
                PutBlock(result, blockIndex, outputBlock);
                previousBlock = outputBlock;
            }

            return result;
        }

        Parallel.For(
            0,
            blockCount,
            new ParallelOptions { CancellationToken = cancellationToken },
            blockIndex =>
            {
                byte[] encryptedBlock = GetBlock(data, blockIndex);
                byte[] previousBlock = blockIndex == 0
                    ? GetInitializationVector()
                    : GetBlock(data, blockIndex - 1);
                byte[] outputBlock = Xor(
                    DecryptBlock(encryptedBlock),
                    previousBlock);
                PutBlock(result, blockIndex, outputBlock);
            });

        return result;
    }

    private byte[] ProcessPcbc(
        byte[] data,
        bool encrypting,
        CancellationToken cancellationToken)
    {
        byte[] result = new byte[data.Length];
        byte[] feedback = GetInitializationVector();
        int blockCount = data.Length / _cipher.BlockSize;

        for (int blockIndex = 0; blockIndex < blockCount; blockIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[] inputBlock = GetBlock(data, blockIndex);

            if (encrypting)
            {
                byte[] encryptedBlock = EncryptBlock(Xor(inputBlock, feedback));
                PutBlock(result, blockIndex, encryptedBlock);
                feedback = Xor(inputBlock, encryptedBlock);
            }
            else
            {
                byte[] plainBlock = Xor(DecryptBlock(inputBlock), feedback);
                PutBlock(result, blockIndex, plainBlock);
                feedback = Xor(plainBlock, inputBlock);
            }
        }

        return result;
    }

    private byte[] ProcessCfb(
        byte[] data,
        bool encrypting,
        CancellationToken cancellationToken)
    {
        byte[] result = new byte[data.Length];
        int blockCount = data.Length / _cipher.BlockSize;

        if (encrypting)
        {
            byte[] previousBlock = GetInitializationVector();
            for (int blockIndex = 0; blockIndex < blockCount; blockIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                byte[] gamma = EncryptBlock(previousBlock);
                byte[] encryptedBlock = Xor(GetBlock(data, blockIndex), gamma);
                PutBlock(result, blockIndex, encryptedBlock);
                previousBlock = encryptedBlock;
            }

            return result;
        }

        Parallel.For(
            0,
            blockCount,
            new ParallelOptions { CancellationToken = cancellationToken },
            blockIndex =>
            {
                byte[] previousBlock = blockIndex == 0
                    ? GetInitializationVector()
                    : GetBlock(data, blockIndex - 1);
                byte[] gamma = EncryptBlock(previousBlock);
                byte[] plainBlock = Xor(GetBlock(data, blockIndex), gamma);
                PutBlock(result, blockIndex, plainBlock);
            });

        return result;
    }

    private byte[] ProcessOfb(
        byte[] data,
        CancellationToken cancellationToken)
    {
        byte[] result = new byte[data.Length];
        byte[] feedback = GetInitializationVector();
        int blockCount = data.Length / _cipher.BlockSize;

        for (int blockIndex = 0; blockIndex < blockCount; blockIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            feedback = EncryptBlock(feedback);
            PutBlock(
                result,
                blockIndex,
                Xor(GetBlock(data, blockIndex), feedback));
        }

        return result;
    }

    private byte[] ProcessCtr(
        byte[] data,
        CancellationToken cancellationToken)
    {
        byte[] result = new byte[data.Length];
        int blockCount = data.Length / _cipher.BlockSize;

        Parallel.For(
            0,
            blockCount,
            new ParallelOptions { CancellationToken = cancellationToken },
            blockIndex =>
            {
                byte[] counter = AddBlockIndex(
                    GetInitializationVector(),
                    blockIndex);
                byte[] gamma = EncryptBlock(counter);
                PutBlock(
                    result,
                    blockIndex,
                    Xor(GetBlock(data, blockIndex), gamma));
            });

        return result;
    }

    private byte[] ProcessRandomDelta(
        byte[] data,
        CancellationToken cancellationToken)
    {
        byte[] result = new byte[data.Length];
        byte[] initial = GetInitializationVector();
        byte[] delta = ((byte[])_additionalParameters[0]).ToArray();
        int blockCount = data.Length / _cipher.BlockSize;

        Parallel.For(
            0,
            blockCount,
            new ParallelOptions { CancellationToken = cancellationToken },
            blockIndex =>
            {
                byte[] sequenceValue = AddScaledDelta(
                    initial,
                    delta,
                    blockIndex);
                byte[] gamma = EncryptBlock(sequenceValue);
                PutBlock(
                    result,
                    blockIndex,
                    Xor(GetBlock(data, blockIndex), gamma));
            });

        return result;
    }

    private byte[] ApplyPadding(byte[] data)
    {
        int remainder = data.Length % _cipher.BlockSize;
        int paddingLength = _cipher.BlockSize - remainder;

        if (_paddingMode == PaddingMode.Zeros && remainder == 0)
        {
            return data.ToArray();
        }

        byte[] result = new byte[data.Length + paddingLength];
        data.CopyTo(result, 0);

        switch (_paddingMode)
        {
            case PaddingMode.Zeros:
                break;
            case PaddingMode.AnsiX923:
                result[^1] = checked((byte)paddingLength);
                break;
            case PaddingMode.Pkcs7:
                Array.Fill(
                    result,
                    checked((byte)paddingLength),
                    data.Length,
                    paddingLength);
                break;
            case PaddingMode.Iso10126:
                Random.Shared.NextBytes(
                    result.AsSpan(data.Length, paddingLength - 1));
                result[^1] = checked((byte)paddingLength);
                break;
            default:
                throw new InvalidOperationException("Unknown padding mode.");
        }

        return result;
    }

    private byte[] RemovePadding(byte[] data)
    {
        if (_paddingMode == PaddingMode.Zeros)
        {
            int length = data.Length;
            while (length > 0 && data[length - 1] == 0)
            {
                length--;
            }

            return data[..length];
        }

        int paddingLength = data[^1];
        if (paddingLength < 1 || paddingLength > _cipher.BlockSize)
        {
            throw new InvalidDataException("Invalid padding length.");
        }

        int paddingStart = data.Length - paddingLength;
        if (_paddingMode == PaddingMode.Pkcs7)
        {
            for (int index = paddingStart; index < data.Length; index++)
            {
                if (data[index] != paddingLength)
                {
                    throw new InvalidDataException("Invalid PKCS7 padding.");
                }
            }
        }
        else if (_paddingMode == PaddingMode.AnsiX923)
        {
            for (int index = paddingStart; index < data.Length - 1; index++)
            {
                if (data[index] != 0)
                {
                    throw new InvalidDataException("Invalid ANSI X.923 padding.");
                }
            }
        }

        return data[..paddingStart];
    }

    private byte[] EncryptBlock(byte[] block)
    {
        byte[] result = _cipher.EncryptBlock(block);
        return ValidateBlockResult(result);
    }

    private byte[] DecryptBlock(byte[] block)
    {
        byte[] result = _cipher.DecryptBlock(block);
        return ValidateBlockResult(result);
    }

    private byte[] ValidateBlockResult(byte[] result)
    {
        if (result is null || result.Length != _cipher.BlockSize)
        {
            throw new InvalidOperationException(
                "The cipher returned a block with an invalid length.");
        }

        return result;
    }

    private byte[] GetInitializationVector() =>
        _initializationVector?.ToArray()
        ?? throw new InvalidOperationException(
            "The selected mode requires an initialization vector.");

    private byte[] GetBlock(byte[] data, int blockIndex)
    {
        byte[] block = new byte[_cipher.BlockSize];
        Buffer.BlockCopy(
            data,
            blockIndex * _cipher.BlockSize,
            block,
            0,
            block.Length);
        return block;
    }

    private void PutBlock(byte[] destination, int blockIndex, byte[] block)
    {
        Buffer.BlockCopy(
            block,
            0,
            destination,
            blockIndex * _cipher.BlockSize,
            _cipher.BlockSize);
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

    private static byte[] AddBlockIndex(byte[] value, int blockIndex)
    {
        byte[] result = value.ToArray();
        ulong carry = checked((uint)blockIndex);

        for (int index = result.Length - 1; index >= 0 && carry != 0; index--)
        {
            ulong sum = result[index] + (carry & 0xFF);
            result[index] = (byte)sum;
            carry = (carry >> 8) + (sum >> 8);
        }

        return result;
    }

    private static byte[] AddScaledDelta(
        byte[] initial,
        byte[] delta,
        int multiplier)
    {
        byte[] result = new byte[initial.Length];
        ulong carry = 0;

        for (int index = initial.Length - 1; index >= 0; index--)
        {
            ulong sum = initial[index]
                + (ulong)delta[index] * checked((uint)multiplier)
                + carry;
            result[index] = (byte)sum;
            carry = sum >> 8;
        }

        return result;
    }

    private void ValidateModeParameters()
    {
        if (_cipherMode != CipherMode.RandomDelta)
        {
            return;
        }

        if (_additionalParameters.Length == 0 ||
            _additionalParameters[0] is not byte[] delta)
        {
            throw new ArgumentException(
                "Random Delta mode requires a byte[] delta as its first " +
                "additional parameter.",
                "additionalParameters");
        }

        if (delta.Length != _cipher.BlockSize)
        {
            throw new ArgumentException(
                "The Random Delta value length must equal the block size.",
                "additionalParameters");
        }
    }

    private static object[] CloneParameters(object[] parameters)
    {
        object[] result = new object[parameters.Length];
        for (int index = 0; index < parameters.Length; index++)
        {
            result[index] = parameters[index] is byte[] bytes
                ? bytes.ToArray()
                : parameters[index];
        }

        return result;
    }

    private static void ValidateFilePaths(
        string inputFilePath,
        string outputFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputFilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputFilePath);
    }
}
