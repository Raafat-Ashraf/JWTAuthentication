using System.ComponentModel.DataAnnotations;

namespace JWTAuthentication.Api.Models;

public class RegisterModel
{
    [StringLength(100)] public string FirstName { get; set; } = null!;

    [StringLength(100)] public string LastName { get; set; } = null!;

    [StringLength(50)] public string Username { get; set; } = null!;

    [StringLength(128)] public string Email { get; set; } = null!;

    [StringLength(256)] public string Password { get; set; } = null!;
}
