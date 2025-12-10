using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Test;

public class test
{
    private const int BoardSize = 5;
    private const char Empty = ' ';
    private const char PlayerSymbol = 'X';
    private const char ComputerSymbol = 'O';

    private readonly char[][] _board;
    
    public static void Main2()
    {
        // Input data
        // const string data = "sN19kC1mS9RB7U5aJJ5tcNw/HMLenqTPBBM/q81v3U+U9fQ9Opb7aflzUJnzqhr+OO/PBe2ib3KLSeCibZ6bag==";
        const string data = "1234567";

        // Compute the SHA-256 hash of the input data
        // var stopwatch1 = Stopwatch.StartNew();
        //
        // Console.WriteLine($"Hashed Data: {ComputeHash(data)}");
        //
        // stopwatch1.Stop();
        // Console.WriteLine($"\nString concatenation using + took: {stopwatch1.ElapsedMilliseconds} ms\n");
        //
        var stopwatch21 = Stopwatch.StartNew();

        Console.WriteLine($"Hashed Data2: {ComputeHash2(data)}");

        stopwatch21.Stop();
        Console.WriteLine($"\nString concatenation using + took: {stopwatch21.ElapsedMilliseconds} ms\n");
        //
        // // Key for AES encryption (128-bit key)
        // const string key = "1234567890123456";
        //
        // var stopwatch1 = Stopwatch.StartNew();
        //
        // // Encrypt the original data
        // var encryptedData = Encrypt(data, key);
        //
        // Console.WriteLine($"Encrypted Data: {encryptedData}");
        //
        // stopwatch1.Stop();
        // Console.WriteLine($"\nString concatenation using + took: {stopwatch1.ElapsedMilliseconds} ms\n");
        //
        // var stopwatch2 = Stopwatch.StartNew();
        //
        // // Decrypt the encrypted data
        // var decryptedData = Decrypt(encryptedData, key);
        // Console.WriteLine($"Decrypted Data: {decryptedData}");
        //
        // stopwatch2.Stop();
        // Console.WriteLine($"\nString concatenation using + took: {stopwatch2.ElapsedMilliseconds} ms\n");
    }

    private static string ComputeHash(string input)
    {
        // Create an instance of the SHA-256 algorithm
        using var sha256 = SHA256.Create();

        // Compute the hash value from the UTF-8 encoded input string
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));

        // Convert the byte array to a lowercase hexadecimal string
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }

    private static string ComputeHash2(string rawData)
    {
        // Create a SHA256
        // using var sha256Hash = SHA256.Create();

        // ComputeHash - returns byte array
        // var bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawData));

        // Convert byte array to a string
        var builder = new StringBuilder();

        foreach (var b in bytes)
        {
            builder.Append(b.ToString("x2"));
        }

        return builder.ToString();
    }

    private static string Encrypt(string plainText, string key)
    {
        using var aesAlg = Aes.Create();

        // Set the key and IV for AES encryption
        aesAlg.Key = Encoding.UTF8.GetBytes(key);
        aesAlg.IV = new byte[aesAlg.BlockSize / 8];

        // Create an encryptor
        var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        // Encrypt the data
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        // Return the encrypted data as a Base64-encoded string
        return Convert.ToBase64String(msEncrypt.ToArray());
    }

    private static string Decrypt(string cipherText, string key)
    {
        using var aesAlg = Aes.Create();
        // Set the key and IV for AES decryption
        aesAlg.Key = Encoding.UTF8.GetBytes(key);
        aesAlg.IV = new byte[aesAlg.BlockSize / 8];

        // Create a decryptor
        var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        // Decrypt the data
        using var msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText));
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);

        // Read the decrypted data from the StreamReader
        return srDecrypt.ReadToEnd();
    }
    private bool IsMoveValid(int row, int col)
    {
        return row is >= 0 and < BoardSize && col is >= 0 and < BoardSize && _board[row][col] == Empty;
    }
    
    private bool IsGameOver()
    {
        return false;
        // return IsBoardFull() || IsGameOver(PlayerSymbol) || IsGameOver(ComputerSymbol);
    }
    
    private int Evaluate()
    {
        // Evaluation function for the current state.
        // You can modify this based on your strategy.
        // hero must write code
        var score = 0;
    
        for (var i = 0; i < BoardSize; i++)
        {
            score += EvaluateLine(_board[i]); // Evaluate row
    
            var column = new char[BoardSize];
    
            for (var j = 0; j < BoardSize; j++)
            {
                column[j] = _board[j][i]; // Build column
            }
    
            score += EvaluateLine(column); // Evaluate column
        }
    
        // Evaluate diagonals
    
        score += EvaluateDiagonals(_board);
    
        return score;
    }
    private int EvaluateLine(char[] line)
    {
        var score = 0;
        int playerCount = 0, computerCount = 0;

        foreach (var cell in line)
        {
            if (cell == PlayerSymbol)
            {
                playerCount++;
                computerCount = 0;
            }
            else if (cell == ComputerSymbol)
            {
                computerCount++;
                playerCount = 0;
            }
            else
            {
                score += GetScore(playerCount, computerCount);
                playerCount = 0;
                computerCount = 0;
            }
        }

        score += GetScore(playerCount, computerCount);
        return score;
    }

    private int EvaluateDiagonals(char[][] board)
    {
        var score = 0;

        for (var i = -BoardSize + 1; i < BoardSize; i++)
        {
            score += EvaluateDiagonal(board, i, true); // Main diagonal
            score += EvaluateDiagonal(board, i, false); // Anti-diagonal
        }

        return score;
    }

    private int EvaluateDiagonal(char[][] board, int offset, bool mainDiagonal)
    {
        var score = 0;
        int playerCount = 0, computerCount = 0;

        for (var i = 0; i < BoardSize; i++)
        {
            var row = i;
            var col = mainDiagonal ? i + offset : BoardSize - 1 - i + offset;

            if (col < 0 || col >= BoardSize) continue;

            if (board[row][col] == PlayerSymbol)
            {
                playerCount++;
                computerCount = 0;
            }
            else if (board[row][col] == ComputerSymbol)
            {
                computerCount++;
                playerCount = 0;
            }
            else
            {
                score += GetScore(playerCount, computerCount);
                playerCount = 0;
                computerCount = 0;
            }
        }

        score += GetScore(playerCount, computerCount);
        return score;
    }

    private int GetScore(int playerCount, int computerCount)
    {
        if (computerCount >= 5) return 10000;
        if (playerCount >= 5) return -10000;

        if (computerCount == 4) return 500;
        if (playerCount == 4) return -500;

        if (computerCount == 3) return 100;
        if (playerCount == 3) return -100;

        return 0;
    }
}