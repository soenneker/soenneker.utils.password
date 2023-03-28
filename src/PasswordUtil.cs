using Soenneker.Extensions.Enumerable;
using Soenneker.Extensions.List;
using Soenneker.Extensions.String;
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;

namespace Soenneker.Utils.Password;

/// <summary>
/// A modern .NET secure password generator.
/// </summary>
/// <remarks>All methods are static, no need to register</remarks>
public class PasswordUtil
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
        char[] charArray = characters.ToCharArray();
        var data = new byte[length];
        generator.GetNonZeroBytes(data);
        var secureCharacters = "";

        foreach (byte num in data)
        {
            secureCharacters += charArray[(int) num % charArray.Length].ToString();
        }

        return secureCharacters;
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
            throw new ArgumentException("Password must be greater than 0");

        var intList = new List<int>();

        if (lower)
            intList.Add(0);

        if (upper)
            intList.Add(1);

        if (number)
            intList.Add(2);

        if (special)
            intList.Add(3);

        if (intList.Empty())
            throw new ArgumentException("Password must contain a type of character");

        if (intList.Count > 1)
            intList.SecureShuffle();

        int toExclusive = length - (intList.Count - 1);

        var result = "";

        using (var generator = RandomNumberGenerator.Create())
        {
            for (var index = 0; index < intList.Count; ++index)
            {
                int num = intList[index];

                int lengthToGenerate = index != intList.Count - 1 ? toExclusive <= 1 ? 1 : intList.Count <= 1 ? toExclusive : RandomNumberGenerator.GetInt32(1, toExclusive) : length - result.Length;
                string? str2 = null;

                switch (num)
                {
                    case 0:
                        str2 = GetSecureCharacters(lengthToGenerate, _lowerChars, generator);
                        break;
                    case 1:
                        str2 = GetSecureCharacters(lengthToGenerate, _upperChars, generator);
                        break;
                    case 2:
                        str2 = GetSecureCharacters(lengthToGenerate, _numberChars, generator);
                        break;
                    case 3:
                        str2 = GetSecureCharacters(lengthToGenerate, _specialJsonSafe, generator);
                        break;
                }

                toExclusive -= lengthToGenerate;
                result += str2;
            }

            if (intList.Count == 1)
                return result;

            return result.SecureShuffle();
        }
    }
}