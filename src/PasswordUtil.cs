using System;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;
using Soenneker.Extensions.String;

namespace Soenneker.Utils.Password;

/// <summary>
/// A modern, high-performance .NET utility for generating secure, random, and optionally unambiguous passwords and strings.
/// </summary>
public static class PasswordUtil
{
    private const string _lowerChars = "abcdefghijklmnopqrstuvwxyz";
    private const string _upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string _numberChars = "1234567890";
    private const string _specialJsonSafe = "!@#$%^*()[]{},.:~_-=";
    private const string _ambiguousChars = "Il1O0S5Z2B8G6gqCG";

    /// <summary>
    /// Removes all ambiguous characters from the given character set.
    /// </summary>
    /// <param name="input">The input character set.</param>
    /// <returns>The character set with ambiguous characters removed.</returns>
    private static string RemoveAmbiguous(string input)
    {
        Span<char> buffer = input.Length <= 256 ? stackalloc char[input.Length] : new char[input.Length];
        var written = 0;

        // Use a fixed-size bool lookup table for fastest ambiguous char checking
        Span<bool> isAmbiguous = stackalloc bool[char.MaxValue + 1];
        foreach (char c in _ambiguousChars)
            isAmbiguous[c] = true;

        foreach (char c in input)
        {
            if (!isAmbiguous[c])
                buffer[written++] = c;
        }

        return new string(buffer.Slice(0, written));
    }

    /// <summary>
    /// Generates a secure random string using the specified character set.
    /// </summary>
    /// <param name="length">The desired length of the result string.</param>
    /// <param name="characters">The allowed characters to use in the result.</param>
    /// <returns>A secure random string of the specified length.</returns>
    [Pure]
    public static string GetSecureCharacters(int length, string characters)
    {
        using var generator = RandomNumberGenerator.Create();
        return GetSecureCharacters(length, characters, generator);
    }

[Pure]
public static string GetSecureCharacters(int length, string characters, RandomNumberGenerator generator)
{
    int charCount = characters.Length;
    if (charCount == 0)
        throw new ArgumentException("Character set must not be empty.");

    int maxAcceptable = (256 / charCount) * charCount;
    var result = new char[length];

    Span<byte> buffer = stackalloc byte[64]; // Small buffer reused
    int written = 0;

    while (written < length)
    {
        int toRead = Math.Min(buffer.Length, length - written);
        generator.GetBytes(buffer.Slice(0, toRead * 2)); // extra to account for discards

        for (int i = 0; i < buffer.Length && written < length; i++)
        {
            byte value = buffer[i];
            if (value < maxAcceptable)
            {
                result[written++] = characters[value % charCount];
            }
        }
    }

    return new string(result);
}
    

    /// <summary>
    /// Generates a secure, URI-safe password using alphanumeric characters.
    /// </summary>
    /// <param name="length">The length of the password to generate.</param>
    /// <param name="excludeAmbiguous">Whether to exclude ambiguous characters (e.g., 'O', '0', 'l', '1').</param>
    /// <returns>A randomly generated alphanumeric password string.</returns>
    [Pure]
    public static string GetUriSafePassword(int length = 24, bool excludeAmbiguous = false)
    {
        return GetPassword(length, true, true, true, false, excludeAmbiguous);
    }

    /// <summary>
    /// Generates a secure password using a combination of character sets.
    /// </summary>
    /// <param name="length">The total length of the password to generate.</param>
    /// <param name="lower">Include lowercase letters.</param>
    /// <param name="upper">Include uppercase letters.</param>
    /// <param name="number">Include numeric digits.</param>
    /// <param name="special">Include special characters.</param>
    /// <param name="excludeAmbiguous">Whether to exclude ambiguous characters (e.g., 'O', '0', 'l', '1').</param>
    /// <returns>A secure password containing a randomized mix of the selected character types.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown if the password length is invalid, no character types are selected,
    /// or ambiguity removal results in an empty character set.
    /// </exception>
    [Pure]
    public static string GetPassword(int length = 24, bool lower = true, bool upper = true, bool number = true, bool special = true, bool excludeAmbiguous = false)
    {
        if (length <= 0)
            throw new ArgumentException("Password length must be greater than 0.");

        var charSets = new string?[4];
        var setCount = 0;

        if (lower) charSets[setCount++] = excludeAmbiguous ? RemoveAmbiguous(_lowerChars) : _lowerChars;
        if (upper) charSets[setCount++] = excludeAmbiguous ? RemoveAmbiguous(_upperChars) : _upperChars;
        if (number) charSets[setCount++] = excludeAmbiguous ? RemoveAmbiguous(_numberChars) : _numberChars;
        if (special) charSets[setCount++] = _specialJsonSafe;

        if (setCount == 0)
            throw new ArgumentException("At least one character type must be enabled.");

        for (var i = 0; i < setCount; i++)
        {
            if (charSets[i].IsNullOrEmpty())
                throw new ArgumentException("Character set became empty after removing ambiguous characters.");
        }

        if (length < setCount)
            throw new ArgumentException("Password length must be at least as many as the selected character types to guarantee inclusion.");

        using var generator = RandomNumberGenerator.Create();

        var result = new char[length];
        var written = 0;

        // Step 1: Guarantee at least one character from each selected set
        for (var i = 0; i < setCount; i++)
        {
            string set = charSets[i]!;
            result[written++] = set[RandomNumberGenerator.GetInt32(set.Length)];
        }

        // Step 2: Fill remaining with random characters from the combined set
        string combined = string.Concat(charSets.AsSpan(0, setCount));
        AppendSecureCharacters(result.AsSpan(written), combined, generator);

        // Step 3: Shuffle the result
        SecureShuffle<char>(result);
        return new string(result);
    }

/// <summary>
/// Fills a destination span with securely generated random characters from a given character set, avoiding modulo bias.
/// </summary>
/// <param name="destination">The span to populate with characters.</param>
/// <param name="characters">The character set to draw from.</param>
/// <param name="generator">An existing random number generator to use.</param>
private static void AppendSecureCharacters(Span<char> destination, string characters, RandomNumberGenerator generator)
{
    int charCount = characters.Length;
    int maxAcceptable = (256 / charCount) * charCount;

    Span<byte> buffer = stackalloc byte[64]; // Tune size for performance/memory

    int written = 0;
    while (written < destination.Length)
    {
        int remaining = destination.Length - written;
        generator.GetBytes(buffer);

        for (int i = 0; i < buffer.Length && written < destination.Length; i++)
        {
            byte b = buffer[i];
            if (b < maxAcceptable)
            {
                destination[written++] = characters[b % charCount];
            }
        }
    }
}

    /// <summary>
    /// Performs an in-place, cryptographically secure shuffle of the elements in a span.
    /// </summary>
    /// <typeparam name="T">The type of the span's elements.</typeparam>
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