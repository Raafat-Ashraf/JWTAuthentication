namespace JWTAuthentication.Api.Models;

public class TokenRequestModel
{
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
}
