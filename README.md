* [ ]

# Лабораторные работы по криптографии

Учебный проект на C# с реализацией блочных шифров **DES** и **DEAL**.

Поддерживаются режимы ECB, CBC, PCBC, CFB, OFB, CTR и Random Delta, а также дополнения Zeros, ANSI X9.23, PKCS#7 и ISO 10126. В проекте есть демонстрация шифрования файлов и набор NUnit-тестов.

## Требования

- .NET SDK 10.0

## Запуск

Из каталога `lab1`:

```bash
# демонстрация DES
dotnet run -- --demo

# демонстрация DEAL
dotnet run -- --deal-demo
```

## Тесты

```bash
dotnet test CryptographyLab1.Tests/CryptographyLab1.Tests.csproj
```
