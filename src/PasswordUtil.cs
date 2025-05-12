using System;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;

namespace Soenneker.Utils.Password;

/// <summary>
/// A modern, high-performance .NET secure password generator for URI-safe and complex passwords.
/// </summary>
/// <remarks>All methods are static and thread-safe. No registration or instantiation required.</remarks>
public static class PasswordUtil
{
    private const string _alphaChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    private const string _lowerChars = "abcdefghijklmnopqrstuvwxyz";
    private const string _upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string _numberChars = "1234567890";
    private const string _specialJsonSafe = "!@#$%^*()[]{},.:~_-=";

    /// <summary>
    /// Generates a secure random string of the specified length using the provided character set.
    /// </summary>
    /// <param name="length">The number of characters in the generated string.</param>
    /// <param name="characters">The character set to select from.</param>
    /// <returns>A securely generated random string.</returns>
    [Pure]
    public static string GetSecureCharacters(int length, string characters)
    {
        using var generator = RandomNumberGenerator.Create();
        return GetSecureCharacters(length, characters, generator);
    }

    /// <summary>
    /// Generates a secure random string of the specified length using the provided character set and RNG instance.
    /// </summary>
    /// <param name="length">The number of characters in the generated string.</param>
    /// <param name="characters">The character set to select from.</param>
    /// <param name="generator">The <see cref="RandomNumberGenerator"/> to use for entropy.</param>
    /// <returns>A securely generated random string.</returns>
    [Pure]
    public static string GetSecureCharacters(int length, string characters, RandomNumberGenerator generator)
    {
        int charCount = characters.Length;
        Span<byte> buffer = stackalloc byte[length];
        generator.GetBytes(buffer);

        Span<char> result = stackalloc char[length];

        for (var i = 0; i < length; i++)
        {
            result[i] = characters[buffer[i] % charCount];
        }

        return new string(result);
    }

    /// <summary>
    /// Generates a secure, URI-safe password using alphanumeric characters.
    /// </summary>
    /// <param name="length">The length of the password to generate.</param>
    /// <returns>A randomly generated URI-safe password.</returns>
    [Pure]
    public static string GetUriSafePassword(int length)
    {
        using var generator = RandomNumberGenerator.Create();
        return GetSecureCharacters(length, _alphaChars, generator);
    }

    /// <summary>
    /// Generates a secure password with a mix of lower-case, upper-case, numeric, and/or special characters.
    /// </summary>
    /// <param name="length">The length of the password. Must be greater than 0.</param>
    /// <param name="lower">Include lowercase characters (a-z).</param>
    /// <param name="upper">Include uppercase characters (A-Z).</param>
    /// <param name="number">Include numeric characters (0-9).</param>
    /// <param name="special">Include JSON-safe special characters (e.g., !@#$%).</param>
    /// <returns>A securely generated password string.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="length"/> is less than or equal to 0, or if no character sets are selected.</exception>
    [Pure]
    public static string GetPassword(int length = 12, bool lower = true, bool upper = true, bool number = true, bool special = true)
    {
        if (length <= 0)
            throw new ArgumentException("Password length must be greater than 0.");

        Span<int> intList = stackalloc int[4];
        var listCount = 0;

        if (lower)
            intList[listCount++] = 0;

        if (upper)
            intList[listCount++] = 1;

        if (number)
            intList[listCount++] = 2;

        if (special)
            intList[listCount++] = 3;

        if (listCount == 0)
            throw new ArgumentException("At least one character type must be enabled.");

        using var generator = RandomNumberGenerator.Create();

        SecureShuffle(intList.Slice(0, listCount));

        Span<char> result = stackalloc char[length];
        var written = 0;

        for (var i = 0; i < listCount; i++)
        {
            int charSetIndex = intList[i];
            int remaining = length - written;
            int remainingTypes = listCount - i;
            int lengthToGenerate = (i == listCount - 1) ? remaining : RandomNumberGenerator.GetInt32(1, remaining - remainingTypes + 2);

            string characters = charSetIndex switch
            {
                0 => _lowerChars,
                1 => _upperChars,
                2 => _numberChars,
                3 => _specialJsonSafe,
                _ => throw new InvalidOperationException("Invalid character set index.")
            };

            AppendSecureCharacters(result.Slice(written, lengthToGenerate), characters, generator);
            written += lengthToGenerate;
        }

        SecureShuffle(result);
        return new string(result);
    }

    /// <summary>
    /// Appends a sequence of random characters from the provided character set to the destination span.
    /// </summary>
    /// <param name="destination">The span to write the generated characters into.</param>
    /// <param name="characters">The character set to select from.</param>
    /// <param name="generator">The <see cref="RandomNumberGenerator"/> to use for entropy.</param>
    private static void AppendSecureCharacters(Span<char> destination, string characters, RandomNumberGenerator generator)
    {
        int charCount = characters.Length;
        Span<byte> buffer = stackalloc byte[destination.Length];
        generator.GetBytes(buffer);

        for (var i = 0; i < buffer.Length; i++)
        {
            destination[i] = characters[buffer[i] % charCount];
        }
    }

    /// <summary>
    /// Performs an in-place cryptographically secure shuffle on the provided span.
    /// </summary>
    /// <typeparam name="T">The type of elements in the span.</typeparam>
    /// <param name="span">The span to shuffle.</param>
    private static void SecureShuffle<T>(Span<T> span)
    {
        for (int i = span.Length - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(0, i + 1);
            (span[i], span[j]) = (span[j], span[i]);
        }
    }
}