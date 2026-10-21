namespace CryptographyLab1;

public enum CipherMode
{
    Ecb,
    Cbc,
    Pcbc,
    Cfb,
    Ofb,
    Ctr,
    RandomDelta
}

public enum PaddingMode
{
    Zeros,
    AnsiX923,
    Pkcs7,
    Iso10126
}
