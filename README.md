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

## Common operations

- `GetSecureCharacters()` - Generates a secure random string using the specified character set.
- `GetUriSafePasswordString()` - Generates a secure, URI-safe password using alphanumeric characters.
- `GetUriSafePassword()` - Generates a secure, URI-safe password using alphanumeric characters.
- `GetPasswordString()` - Generates a secure password using a combination of character sets. Guarantees inclusion of at least one character from each selected set, then shuffles.
- `GetPassword()` - Generates a secure password using a combination of character sets. Guarantees inclusion of at least one character from each selected set, then shuffles.
