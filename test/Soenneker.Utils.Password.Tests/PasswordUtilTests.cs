using FluentAssertions;
using Soenneker.Tests.Unit;
using Xunit;

namespace Soenneker.Utils.Password.Tests;

public class PasswordUtilTests : UnitTest
{
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
}