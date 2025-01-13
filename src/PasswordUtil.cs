using System;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;
using System.Text;

namespace Soenneker.Utils.Password;

/// <summary>
/// A modern .NET secure password generator.
/// </summary>
/// <remarks>All methods are static, no need to register</remarks>
public static class PasswordUtil
{
    private const string _alphaChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    private const string _lowerChars = "abcdefghijklmnopqrstuvwxyz";
    private const string _upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string _numberChars = "1234567890";
    private const string _specialJsonSafe = "!@#$%^*()[]{},.:~_-=";

    [Pure]
    public static string GetSecureCharacters(int length, string characters)
    {
        using (var generator = RandomNumberGenerator.Create())
        {
            return GetSecureCharacters(length, characters, generator);
        }
    }

    [Pure]
    public static string GetSecureCharacters(int length, string characters, RandomNumberGenerator generator)
    {
        var result = new StringBuilder(length);
        int charCount = characters.Length;

        var data = new byte[length];
        generator.GetNonZeroBytes(data);

        for (var i = 0; i < data.Length; i++)
        {
            byte num = data[i];
            result.Append(characters[num % charCount]);
        }

        return result.ToString();
    }

    [Pure]
    public static string GetUriSafePassword(int length)
    {
        using (var generator = RandomNumberGenerator.Create())
        {
            return GetSecureCharacters(length, _alphaChars, generator);
        }
    }

    [Pure]
    public static string GetPassword(int length = 12, bool lower = true, bool upper = true, bool number = true, bool special = true)
    {
        if (length <= 0)
            throw new ArgumentException("Password length must be greater than 0.");

        Span<int> intList = stackalloc int[4];
        int listCount = 0;

        if (lower) intList[listCount++] = 0;
        if (upper) intList[listCount++] = 1;
        if (number) intList[listCount++] = 2;
        if (special) intList[listCount++] = 3;

        if (listCount == 0)
            throw new ArgumentException("At least one character type must be enabled.");

        using var generator = RandomNumberGenerator.Create();

        // Shuffle intList securely
        SecureShuffle(intList.Slice(0, listCount));

        var result = new StringBuilder(length);
        int remainingLength = length;

        for (int i = 0; i < listCount; i++)
        {
            int charSetIndex = intList[i];
            int lengthToGenerate = i == listCount - 1
                ? remainingLength
                : RandomNumberGenerator.GetInt32(1, remainingLength - (listCount - i - 1) + 1);

            string characters = charSetIndex switch
            {
                0 => _lowerChars,
                1 => _upperChars,
                2 => _numberChars,
                3 => _specialJsonSafe,
                _ => throw new InvalidOperationException("Invalid character set index.")
            };

            AppendSecureCharacters(result, lengthToGenerate, characters, generator);

            remainingLength -= lengthToGenerate;
        }

        return SecureShuffle(result.ToString());
    }

    private static void AppendSecureCharacters(StringBuilder builder, int count, string characters, RandomNumberGenerator generator)
    {
        Span<byte> buffer = stackalloc byte[count];
        generator.GetNonZeroBytes(buffer);
        int charCount = characters.Length;

        foreach (var b in buffer)
        {
            builder.Append(characters[b % charCount]);
        }
    }

    private static void SecureShuffle<T>(Span<T> span)
    {
        for (int i = span.Length - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(0, i + 1);
            (span[i], span[j]) = (span[j], span[i]);
        }
    }

    private static string SecureShuffle(string input)
    {
        Span<char> chars = stackalloc char[input.Length];
        input.AsSpan().CopyTo(chars);
        SecureShuffle(chars);
        return new string(chars);
    }
}