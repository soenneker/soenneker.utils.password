using System;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
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

    // Cache an ambiguity lookup once, rather than rebuilding per call.
    private static readonly bool[] _ambiguousMap = BuildAmbiguousMap();

    private static bool[] BuildAmbiguousMap()
    {
        var map = new bool[char.MaxValue + 1];
        foreach (char c in _ambiguousChars)
            map[c] = true;
        return map;
    }

    /// <summary>Removes all ambiguous characters from the given character set.</summary>
    private static string RemoveAmbiguous(string input)
    {
        if (input.Length == 0)
            return string.Empty;

        Span<char> buffer = input.Length <= 256 ? stackalloc char[input.Length] : new char[input.Length];
        var written = 0;

        foreach (char c in input)
        {
            if (!_ambiguousMap[c])
                buffer[written++] = c;
        }

        return new string(buffer[..written]);
    }

    /// <summary>Generates a secure random string using the specified character set.</summary>
    [Pure]
    public static string GetSecureCharacters(int length, string characters)
    {
        using var generator = RandomNumberGenerator.Create();
        return GetSecureCharacters(length, characters, generator);
    }

    /// <summary>Generates a secure random string using the specified character set and RNG.</summary>
    [Pure]
    public static string GetSecureCharacters(int length, string characters, RandomNumberGenerator generator)
    {
        if (characters.IsNullOrEmpty())
            throw new ArgumentException("Character set must not be empty.", nameof(characters));
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));
        if (length > 1_000_000)
            throw new ArgumentOutOfRangeException(nameof(length), "Requested length is unreasonably large.");

        ReadOnlySpan<char> chars = characters.AsSpan();
        var result = new char[length];

        FillWithSecureCharacters(result.AsSpan(), chars, generator);
        return new string(result);
    }

    /// <summary>Generates a secure, URI-safe password using alphanumeric characters.</summary>
    [Pure]
    public static string GetUriSafePassword(int length = 24, bool excludeAmbiguous = false)
    {
        return GetPassword(length, true, true, true, false, excludeAmbiguous);
    }

    /// <summary>
    /// Generates a secure password using a combination of character sets.
    /// Guarantees inclusion of at least one character from each selected set, then shuffles.
    /// </summary>
    [Pure]
    public static string GetPassword(int length = 24, bool lower = true, bool upper = true, bool number = true, bool special = true, bool excludeAmbiguous = false)
    {
        if (length <= 0)
            throw new ArgumentException("Password length must be greater than 0.", nameof(length));

        // Use a tiny array of strings (OK on heap, negligible). Avoid Span<ReadOnlySpan<char>> (illegal).
        var sets = new string?[4];
        var setCount = 0;

        if (lower) sets[setCount++] = excludeAmbiguous ? RemoveAmbiguous(_lowerChars) : _lowerChars;
        if (upper) sets[setCount++] = excludeAmbiguous ? RemoveAmbiguous(_upperChars) : _upperChars;
        if (number) sets[setCount++] = excludeAmbiguous ? RemoveAmbiguous(_numberChars) : _numberChars;
        if (special) sets[setCount++] = _specialJsonSafe;

        if (setCount == 0)
            throw new ArgumentException("At least one character type must be enabled.");
        
        for (var i = 0; i < setCount; i++)
        {
            if (sets[i].IsNullOrEmpty())
                throw new ArgumentException("Character set became empty after removing ambiguous characters.");
        }

        if (length < setCount)
            throw new ArgumentException("Password length must be at least the number of selected character types to guarantee inclusion.");

        using var rng = RandomNumberGenerator.Create();

        var result = new char[length];
        var written = 0;

        // Step 1: guarantee one from each set
        for (var i = 0; i < setCount; i++)
        {
            string set = sets[i]!;
            int idx = GetInt32(rng, set.Length);
            result[written++] = set[idx];
        }

        // Step 2: build a combined alphabet without allocating a managed string
        var combinedLen = 0;
        for (var i = 0; i < setCount; i++)
            combinedLen += sets[i]!.Length;

        Span<char> combined = combinedLen <= 128 ? stackalloc char[combinedLen] : new char[combinedLen];
        var pos = 0;
        for (var i = 0; i < setCount; i++)
        {
            string s = sets[i]!;
            s.AsSpan().CopyTo(combined.Slice(pos, s.Length));
            pos += s.Length;
        }

        // Fill remainder from combined
        FillWithSecureCharacters(result.AsSpan(written), combined, rng);

        // Step 3: shuffle
        SecureShuffle(result.AsSpan(), rng);

        return new string(result);
    }

    /// <summary>
    /// Fills a destination span with securely generated random characters from a given character set, avoiding modulo bias.
    /// Works efficiently for sets ≤ 256; falls back to GetInt32 for larger sets.
    /// </summary>
    private static void FillWithSecureCharacters(Span<char> destination, ReadOnlySpan<char> characters, RandomNumberGenerator rng)
    {
        int charCount = characters.Length;

        if (charCount == 0)
            throw new ArgumentException("Character set must not be empty.", nameof(characters));

        if (charCount == 1)
        {
            destination.Fill(characters[0]);
            return;
        }

        // Fast path for common case (≤ 256)
        if (charCount <= 256)
        {
            int maxAcceptable = 256 / charCount * charCount; // rejection-sampling boundary
            Span<byte> buffer = stackalloc byte[64];

            var written = 0;
            while (written < destination.Length)
            {
                rng.GetBytes(buffer);

                for (var i = 0; i < buffer.Length && written < destination.Length; i++)
                {
                    byte b = buffer[i];
                    if (b < maxAcceptable)
                        destination[written++] = characters[b % charCount];
                }
            }

            CryptographicOperations.ZeroMemory(buffer);
            return;
        }

        // General path for large alphabets (> 256)
        for (var i = 0; i < destination.Length; i++)
            destination[i] = characters[GetInt32(rng, charCount)];
    }

    /// <summary>In-place, cryptographically secure Fisher–Yates shuffle.</summary>
    private static void SecureShuffle<T>(Span<T> span, RandomNumberGenerator rng)
    {
        for (int i = span.Length - 1; i > 0; i--)
        {
            int j = GetInt32(rng, i + 1);
            (span[i], span[j]) = (span[j], span[i]);
        }
    }

    // Use the instance RNG rather than the static API for consistency & testability.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetInt32(RandomNumberGenerator rng, int exclusiveMax)
    {
        // Equivalent to RandomNumberGenerator.GetInt32(exclusiveMax), but bound to the provided instance.
        if (exclusiveMax <= 0)
            throw new ArgumentOutOfRangeException(nameof(exclusiveMax));

        // Use 32-bit rejection sampling
        Span<byte> bytes = stackalloc byte[4];
        uint limit = uint.MaxValue / (uint)exclusiveMax * (uint)exclusiveMax;
        uint value;
        do
        {
            rng.GetBytes(bytes);
            value = BitConverter.ToUInt32(bytes);
        } while (value >= limit);

        return (int)(value % (uint)exclusiveMax);
    }
}