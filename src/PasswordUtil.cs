using System;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Soenneker.Extensions.Spans.Chars;
using Soenneker.Extensions.Spans.Generics;
using Soenneker.Extensions.Spans.Bytes;

namespace Soenneker.Utils.Password;

/// <summary>
/// A modern, high-performance .NET utility for generating secure, random, and optionally unambiguous passwords and strings.
/// </summary>
public static class PasswordUtil
{
    private static ReadOnlySpan<char> LowerChars => "abcdefghijklmnopqrstuvwxyz";
    private static ReadOnlySpan<char> UpperChars => "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static ReadOnlySpan<char> NumberChars => "1234567890";
    private static ReadOnlySpan<char> SpecialJsonSafe => "!@#$%^*()[]{},.:~_-=";
    private static ReadOnlySpan<char> AmbiguousChars => "Il1O0S5Z2B8G6gqCG";

    // Cache an ambiguity lookup once, rather than rebuilding per call.
    private static readonly bool[] _ambiguousMap = BuildAmbiguousMap();

    private const int _stackAllocLength = 256;
    private const int _rngByteBufferSize = 128;

    private static bool[] BuildAmbiguousMap()
    {
        var map = new bool[char.MaxValue + 1];

        foreach (char c in AmbiguousChars)
        {
            map[c] = true;
        }

        return map;
    }

    /// <summary>Generates a secure random string using the specified character set.</summary>
    [Pure]
    public static string GetSecureCharacters(int length, string characters)
    {
        using var generator = RandomNumberGenerator.Create();
        return GetSecureCharacters(length, characters, generator);
    }

    /// <summary>
    /// Generates a secure random string using the specified character set.
    /// </summary>
    /// <remarks>
    /// This allocates a managed <see cref="string"/>, which cannot be securely cleared.
    /// For sensitive secrets (passwords, keys), prefer <see cref="GetPassword"/> with a caller-owned <see cref="Span{Char}"/>.
    /// </remarks>
    [Pure]
    public static string GetSecureCharacters(int length, string characters, RandomNumberGenerator generator)
    {
        return GetSecureCharacters(length, characters.AsSpan(), generator);
    }

    /// <summary>
    /// Generates a secure random string using the specified character set.
    /// </summary>
    /// <remarks>
    /// This allocates a managed <see cref="string"/>, which cannot be securely cleared.
    /// For sensitive secrets (passwords, keys), prefer <see cref="GetPassword"/> with a caller-owned <see cref="Span{Char}"/>.
    /// </remarks>
    [Pure]
    public static string GetSecureCharacters(int length, ReadOnlySpan<char> characters, RandomNumberGenerator generator)
    {
        if (characters.IsEmpty)
            throw new ArgumentException("Character set must not be empty.", nameof(characters));

        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));

        if (length > 1_000_000)
            throw new ArgumentOutOfRangeException(nameof(length), "Requested length is unreasonably large.");

        Span<char> buffer = length <= _stackAllocLength ? stackalloc char[length] : new char[length];

        FillWithSecureCharacters(buffer, characters, generator);

        var result = new string(buffer);

        if (length > _stackAllocLength)
            buffer.SecureZero();

        return result;
    }

    /// <summary>Generates a secure, URI-safe password using alphanumeric characters.</summary>
    /// <remarks>You should use GetUriSafePassword() if possible</remarks>
    [Pure]
    public static string GetUriSafePasswordString(int length = 24, bool excludeAmbiguous = false)
    {
        return GetPasswordString(length, true, true, true, false, excludeAmbiguous);
    }

    public static void GetUriSafePassword(Span<char> destination, bool excludeAmbiguous = false)
    {
        GetPassword(destination, true, true, true, false, excludeAmbiguous);
    }

    /// <summary>
    /// Generates a secure password using a combination of character sets.
    /// Guarantees inclusion of at least one character from each selected set, then shuffles.
    /// </summary>
    /// <remarks>You should use GetPassword() if possible</remarks>
    [Pure]
    public static string GetPasswordString(int length = 24, bool includeLowers = true, bool includeUppers = true, bool includeNumbers = true,
        bool includeSpecials = true, bool excludeAmbiguous = false)
    {
        Span<char> buffer = length <= _stackAllocLength ? stackalloc char[length] : new char[length];

        GetPassword(buffer, includeLowers, includeUppers, includeNumbers, includeSpecials, excludeAmbiguous);

        var result = new string(buffer);

        buffer.SecureZero();

        return result;
    }

    /// <summary>
    /// Generates a secure password using a combination of character sets.
    /// Guarantees inclusion of at least one character from each selected set, then shuffles.
    /// </summary>
    public static void GetPassword(Span<char> destination, bool includeLowers = true, bool includeUppers = true, bool includeNumbers = true,
        bool includeSpecials = true, bool excludeAmbiguous = false)
    {
        int length = destination.Length;

        if (length <= 0)
            throw new ArgumentException("Password length must be greater than 0.", nameof(length));

        // Allocate buffers for filtered character sets (only needed for ambiguous filtering)
        Span<char> lowerBuffer = stackalloc char[LowerChars.Length];
        Span<char> upperBuffer = stackalloc char[UpperChars.Length];
        Span<char> numberBuffer = stackalloc char[NumberChars.Length];

        // Get the character sets as spans
        ReadOnlySpan<char> lowerSet = includeLowers ? GetFilteredSet(LowerChars, excludeAmbiguous, lowerBuffer) : ReadOnlySpan<char>.Empty;
        ReadOnlySpan<char> upperSet = includeUppers ? GetFilteredSet(UpperChars, excludeAmbiguous, upperBuffer) : ReadOnlySpan<char>.Empty;
        ReadOnlySpan<char> numberSet = includeNumbers ? GetFilteredSet(NumberChars, excludeAmbiguous, numberBuffer) : ReadOnlySpan<char>.Empty;

        ReadOnlySpan<char> specialSet = includeSpecials ? SpecialJsonSafe : ReadOnlySpan<char>.Empty;

        // Count active sets and validate
        var setCount = 0;
        if (!lowerSet.IsEmpty)
            setCount++;

        if (!upperSet.IsEmpty)
            setCount++;

        if (!numberSet.IsEmpty)
            setCount++;

        if (!specialSet.IsEmpty)
            setCount++;

        if (setCount == 0)
            throw new ArgumentException("At least one character type must be enabled.");

        // Validate sets are not empty (if included, they must have characters after filtering)
        if (includeLowers && lowerSet.IsEmpty)
            throw new ArgumentException("Character set became empty after removing ambiguous characters.");

        if (includeUppers && upperSet.IsEmpty)
            throw new ArgumentException("Character set became empty after removing ambiguous characters.");

        if (includeNumbers && numberSet.IsEmpty)
            throw new ArgumentException("Character set became empty after removing ambiguous characters.");

        if (includeSpecials && specialSet.IsEmpty)
            throw new ArgumentException("Character set became empty after removing ambiguous characters.");

        if (length < setCount)
            throw new ArgumentException("Password length must be at least the number of selected character types to guarantee inclusion.");

        var written = 0;

        // Step 1: guarantee one from each set
        if (!lowerSet.IsEmpty)
        {
            int idx = RandomNumberGenerator.GetInt32(lowerSet.Length);
            destination[written++] = lowerSet[idx];
        }

        if (!upperSet.IsEmpty)
        {
            int idx = RandomNumberGenerator.GetInt32(upperSet.Length);
            destination[written++] = upperSet[idx];
        }

        if (!numberSet.IsEmpty)
        {
            int idx = RandomNumberGenerator.GetInt32(numberSet.Length);
            destination[written++] = numberSet[idx];
        }

        if (!specialSet.IsEmpty)
        {
            int idx = RandomNumberGenerator.GetInt32(specialSet.Length);
            destination[written++] = specialSet[idx];
        }

        // Step 2: build a combined alphabet
        var combinedLen = 0;

        if (!lowerSet.IsEmpty)
            combinedLen += lowerSet.Length;

        if (!upperSet.IsEmpty)
            combinedLen += upperSet.Length;

        if (!numberSet.IsEmpty)
            combinedLen += numberSet.Length;

        if (!specialSet.IsEmpty)
            combinedLen += specialSet.Length;

        Span<char> combined = combinedLen <= _stackAllocLength ? stackalloc char[combinedLen] : new char[combinedLen];

        var pos = 0;

        if (!lowerSet.IsEmpty)
        {
            lowerSet.CopyTo(combined.Slice(pos, lowerSet.Length));
            pos += lowerSet.Length;
        }

        if (!upperSet.IsEmpty)
        {
            upperSet.CopyTo(combined.Slice(pos, upperSet.Length));
            pos += upperSet.Length;
        }

        if (!numberSet.IsEmpty)
        {
            numberSet.CopyTo(combined.Slice(pos, numberSet.Length));
            pos += numberSet.Length;
        }

        if (!specialSet.IsEmpty)
        {
            specialSet.CopyTo(combined.Slice(pos, specialSet.Length));
        }

        // It all points to a static singleton, doesn't need disposal
        var rng = RandomNumberGenerator.Create();

        // Fill remainder from combined
        FillWithSecureCharacters(destination[written..], combined, rng);

        combined.SecureZero();

        // Step 3: shuffle
        destination.SecureShuffle();
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
            Span<byte> buffer = stackalloc byte[_rngByteBufferSize];

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

            buffer.SecureZero();
            return;
        }

        // General path for large alphabets (> 256)
        for (var i = 0; i < destination.Length; i++)
            destination[i] = characters[RandomNumberGenerator.GetInt32(charCount)];
    }

    /// <summary>
    /// Returns either the original span or a filtered span in <paramref name="buffer"/> with ambiguous characters removed,
    /// without allocating a new string.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ReadOnlySpan<char> GetFilteredSet(ReadOnlySpan<char> source, bool excludeAmbiguous, Span<char> buffer)
    {
        if (!excludeAmbiguous)
            return source;

        var written = 0;

        for (var i = 0; i < source.Length; i++)
        {
            char c = source[i];

            if (!_ambiguousMap[c])
                buffer[written++] = c;
        }

        return buffer[..written];
    }
}