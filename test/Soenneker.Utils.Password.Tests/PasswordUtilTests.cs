using AwesomeAssertions;
using Soenneker.Tests.Unit;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Soenneker.Utils.Password.Tests;

public class PasswordUtilTests : UnitTest
{
    private const string AllowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    public PasswordUtilTests(ITestOutputHelper output) : base(output)
    {
    }

    [Fact]
    public void GetUriSafePassword_should_return_string_of_same_length()
    {
        string result = PasswordUtil.GetUriSafePassword(20);

        result.Should().NotBeNullOrEmpty();
        result.Length.Should().Be(20);
    }

    [Fact]
    public void GetPassword_should_return_password_with_default_length()
    {
        string result = PasswordUtil.GetPassword();
        result.Should().NotBeNullOrEmpty();
        result.Length.Should().Be(24);
    }

    [Fact]
    public void GetPassword_with_ambiguous_should_give_expected_length()
    {
        string result = PasswordUtil.GetPassword(excludeAmbiguous: true);
        result.Should().NotBeNullOrEmpty();
        result.Length.Should().Be(24);
    }

    [Fact]
    public void GetUriSafePassword_should_not_be_null()
    {
        string result = PasswordUtil.GetUriSafePassword(excludeAmbiguous: true);
        result.Should().NotBeNullOrEmpty();
        result.Length.Should().Be(24);
    }

    [Fact]
    public void GetUriSafePassword_should_generate_expected_length()
    {
        string password = PasswordUtil.GetUriSafePassword(32);
        password.Should().NotBeNullOrWhiteSpace();
        password.Length.Should().Be(32);
        password.All(c => char.IsLetterOrDigit(c)).Should().BeTrue();
    }

    [Fact]
    public void GetUriSafePassword_should_exclude_ambiguous_when_requested()
    {
        string password = PasswordUtil.GetUriSafePassword(64, excludeAmbiguous: true);
        password.Should().NotBeNullOrWhiteSpace();
        password.Should().NotContainAny("Il1O0S5Z2B8G6gqCG");
    }

    [Theory]
    [InlineData(10, true, false, false, false)]
    [InlineData(10, false, true, false, false)]
    [InlineData(10, false, false, true, false)]
    [InlineData(10, false, false, false, true)]
    public void GetPassword_should_include_required_char_types(int length, bool lower, bool upper, bool number, bool special)
    {
        string password = PasswordUtil.GetPassword(length, lower, upper, number, special);
        password.Length.Should().Be(length);

        if (lower) password.Any(char.IsLower).Should().BeTrue();
        if (upper) password.Any(char.IsUpper).Should().BeTrue();
        if (number) password.Any(char.IsDigit).Should().BeTrue();
        if (special) password.Any(c => "!@#$%^*()[]{},.:~_-=".Contains(c)).Should().BeTrue();
    }

    [Fact]
    public void GetPassword_should_throw_if_all_sets_disabled()
    {
        Action act = () => PasswordUtil.GetPassword(10, false, false, false, false);
        act.Should().Throw<ArgumentException>().WithMessage("*At least one character type*");
    }

    [Fact]
    public void GetPassword_should_throw_if_too_short_for_sets()
    {
        Action act = () => PasswordUtil.GetPassword(2, true, true, true, false);
        act.Should().Throw<ArgumentException>().WithMessage("Password length must be at least the number of selected character types to guarantee inclusion.");
    }

    [Fact]
    public void GetSecureCharacters_should_generate_expected_length()
    {
        var chars = "ABC123";
        string result = PasswordUtil.GetSecureCharacters(20, chars);
        result.Should().HaveLength(20);
        result.All(c => chars.Contains(c)).Should().BeTrue();
    }

    [Fact]
    public void GetSecureCharacters_should_throw_on_empty_charset()
    {
        Action act = () => PasswordUtil.GetSecureCharacters(10, "");
        act.Should().Throw<ArgumentException>().WithMessage("*must not be empty*");
    }

    [Fact]
    public void RemoveAmbiguous_should_remove_all_ambiguous_chars()
    {
        var input = "ABCDEFGIl1O0S5Z2B8G6gqCG";
        var cleaned = typeof(PasswordUtil)
                      .GetMethod("RemoveAmbiguous", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
                      .Invoke(null, new object[] { input }) as string;

        cleaned.Should().NotContainAny("Il1O0S5Z2B8G6gqCG");
    }

    [Fact]
    public void GetPassword_should_exclude_ambiguous_when_requested()
    {
        string password = PasswordUtil.GetPassword(64, includeLowers: true, includeUppers: true, includeNumbers: true, includeSpecials: false, excludeAmbiguous: true);
        password.Should().NotContainAny("Il1O0S5Z2B8G6gqCG");
    }

    [Fact]
    public void Generated_passwords_should_be_random()
    {
        List<string> passwords = Enumerable.Range(0, 10)
                                           .Select(_ => PasswordUtil.GetPassword(32))
                                           .ToList();

        passwords.Distinct().Count().Should().BeGreaterThan(1);
    }

    [Theory]
    [InlineData(256)]
    [InlineData(2048)]
    [InlineData(10000)]
    public void GetSecureCharacters_should_generate_long_valid_string(int length)
    {
        string result = PasswordUtil.GetSecureCharacters(length, AllowedChars);

        result.Should().NotBeNull();
        result.Length.Should().Be(length);
        result.All(c => AllowedChars.Contains(c)).Should().BeTrue();
    }

    [Theory]
    [InlineData(512)]
    [InlineData(2048)]
    [InlineData(8192)]
    public void GetPassword_should_generate_random_password_of_correct_length(int length)
    {
        string password = PasswordUtil.GetPassword(length, includeLowers: true, includeUppers: true, includeNumbers: true, includeSpecials: true, excludeAmbiguous: true);

        password.Should().NotBeNullOrWhiteSpace();
        password.Length.Should().Be(length);
    }

    [Fact]
    public void GetSecureCharacters_should_produce_nonidentical_outputs_on_repeated_calls()
    {
        string one = PasswordUtil.GetSecureCharacters(2048, AllowedChars);
        string two = PasswordUtil.GetSecureCharacters(2048, AllowedChars);

        one.Should().NotBeEquivalentTo(two); // Allow possibility of rare collisions but very unlikely
    }
}