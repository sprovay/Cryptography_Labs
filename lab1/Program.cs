using CryptographyLab1;
// dotnet test CryptographyLab1.Tests/CryptographyLab1.Tests.csproj
int dealDemoArgumentIndex = Array.IndexOf(args, "--deal-demo");
if (dealDemoArgumentIndex >= 0)
{
    string inputDirectory = dealDemoArgumentIndex + 1 < args.Length
        ? args[dealDemoArgumentIndex + 1]
        : Path.Combine(Environment.CurrentDirectory, "test-files");
    string outputDirectory = dealDemoArgumentIndex + 2 < args.Length
        ? args[dealDemoArgumentIndex + 2]
        : Path.Combine(Environment.CurrentDirectory, "deal-demo");

    await DealDemonstration.RunAsync(inputDirectory, outputDirectory);
    return;
}

int demoArgumentIndex = Array.IndexOf(args, "--demo");
if (demoArgumentIndex >= 0)
{
    string inputDirectory = demoArgumentIndex + 1 < args.Length
        ? args[demoArgumentIndex + 1]
        : Path.Combine(Environment.CurrentDirectory, "test-files");
    string outputDirectory = demoArgumentIndex + 2 < args.Length
        ? args[demoArgumentIndex + 2]
        : Path.Combine(Environment.CurrentDirectory, "des-demo");

    await DesDemonstration.RunAsync(inputDirectory, outputDirectory);
    return;
}
