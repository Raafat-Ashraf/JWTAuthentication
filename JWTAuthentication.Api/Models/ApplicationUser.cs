using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace JWTAuthentication.Api.Models;

public class ApplicationUser : IdentityUser
{
    [MaxLength(50)]
    public string FirstName { get; set; } = null!;

    [MaxLength(50)]
    public string LastName { get; set; } = null!;
}
