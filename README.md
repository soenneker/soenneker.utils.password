[![](https://img.shields.io/nuget/v/Soenneker.Utils.Password.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.Password/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.password/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.utils.password/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/Soenneker.Utils.Password.svg?style=for-the-badge)](https://www.nuget.org/packages/Soenneker.Utils.Password/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.password/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.utils.password/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Utils.Password
A modern .NET secure password generator.

## Installation

```bash
dotnet add package Soenneker.Utils.Password
```

## Quick start

```csharp
using Soenneker.Utils.Password;
```

Call the static `PasswordUtil` methods directly; no dependency-injection registration is required.

## Fill a caller-owned buffer

```csharp
using System.Runtime.InteropServices;
using System.Security.Cryptography;

Span<char> password = stackalloc char[32];

try
{
    PasswordUtil.GetPassword(
        password,
        includeLowers: true,
        includeUppers: true,
        includeNumbers: true,
        includeSpecials: true,
        excludeAmbiguous: true);

    UsePassword(password);
}
finally
{
    CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(password));
}
```

`GetPassword` fills the entire destination, guarantees at least one character from every enabled
class, fills the remainder from the combined alphabet, and securely shuffles the result. The
destination must be at least as long as the number of enabled classes. At least one class must be
enabled.

The special-character alphabet is `!@#$%^*()[]{},.:~_-=`. Ambiguous filtering applies to the
letter and number alphabets; it does not modify the special alphabet.

## URI-safe passwords

```csharp
Span<char> token = stackalloc char[24];
PasswordUtil.GetUriSafePassword(token, excludeAmbiguous: true);

try
{
    UseToken(token);
}
finally
{
    CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(token));
}
```

The URI-safe methods use only ASCII lowercase letters, uppercase letters, and digits. They do not
perform URL encoding and do not include punctuation.

## String convenience methods

```csharp
string password = PasswordUtil.GetPasswordString(length: 32);
string token = PasswordUtil.GetUriSafePasswordString(length: 24);
string digits = PasswordUtil.GetSecureCharacters(8, "0123456789");
```

`GetSecureCharacters` samples uniformly from the supplied alphabet without modulo bias, but it
does not guarantee every character or category appears. Its overload accepting a
`RandomNumberGenerator` leaves that caller-owned generator open.

The string-returning methods are convenient, but managed strings cannot be reliably cleared from
memory. Prefer the span overloads for secrets whose lifetime you need to limit, and securely clear the
buffer in a `finally` block. Clearing the caller's buffer cannot erase copies already made by
logging, interpolation, encoding, or another API.
