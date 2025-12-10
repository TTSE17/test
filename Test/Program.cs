/**/


namespace Test;

public delegate void MyDelegate(string message);

internal abstract class Program
{
    private static void Main(string[] args)
    {
        Console.WriteLine($"Your current TOTP code is:");
    }
}