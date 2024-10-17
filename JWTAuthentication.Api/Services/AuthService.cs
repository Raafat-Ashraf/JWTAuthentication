using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JWTAuthentication.Api.Helpers;
using JWTAuthentication.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthentication.Api.Services;

public class AuthService(
    UserManager<ApplicationUser> userManager,
    RoleManager<IdentityRole> roleManager,
    IOptions<Jwt> jwt) : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;

    private readonly Jwt _jwt = jwt.Value;


    public async Task<AuthModel> RegisterAsync(RegisterModel model)
    {
        if (await _userManager.FindByEmailAsync(model.Email) is not null)
            return new AuthModel { Message = "Email is already registered!" };

        if (await _userManager.FindByNameAsync(model.Username) is not null)
            return new AuthModel { Message = "Username is already registered!" };

        var user = new ApplicationUser
        {
            UserName = model.Username,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            var errors = result.Errors.Aggregate(string.Empty, (current, error) => current + $"{error.Description},");
            return new AuthModel { Message = errors };
        }

        await _userManager.AddToRoleAsync(user, "User");
        var jwtSecurityToken = await GenerateJwtTokenAsync(user);

        var refreshToken = GenerateRefreshToken();

        return new AuthModel
        {
            Email = user.Email,
            // ExpiresOn = jwtSecurityToken.ValidTo,
            IsAuthenticated = true,
            Roles = ["User"],
            Username = user.UserName,
            Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
            RefreshToken = refreshToken.Token,
            RefreshTokenExpiration = refreshToken.ExpiresOn
        };
    }

    public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
    {
        var authModel = new AuthModel();

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
        {
            authModel.Message = "Email or password is incorrect!";
            return authModel;
        }

        var jwtSecurityToken = await GenerateJwtTokenAsync(user);
        var rolesList = await _userManager.GetRolesAsync(user);

        authModel.IsAuthenticated = true;
        authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        authModel.Email = user.Email!;
        authModel.Username = user.UserName!;
        // authModel.ExpiresOn = jwtSecurityToken.ValidTo;
        authModel.Roles = rolesList.ToList();

        if (user.RefreshTokens.Any(x => x.IsActive))
        {
            var activeRefreshTokens = user.RefreshTokens.FirstOrDefault(x => x.IsActive);
            authModel.RefreshToken = activeRefreshTokens!.Token;
            authModel.RefreshTokenExpiration = activeRefreshTokens.ExpiresOn;
        }
        else
        {
            var refreshToken = GenerateRefreshToken();
            authModel.RefreshToken = refreshToken.Token;
            authModel.RefreshTokenExpiration = refreshToken.ExpiresOn;

            user.RefreshTokens.Add(refreshToken);
            await _userManager.UpdateAsync(user);
        }

        return authModel;
    }

    public async Task<string> AddRoleAsync(AddRoleModel model)
    {
        if (await _userManager.FindByIdAsync(model.UserId) is not { } user ||
            !await _roleManager.RoleExistsAsync(model.Role))
            return "Invalid user Id or password Role";

        if (await _userManager.IsInRoleAsync(user, model.Role))
            return "User already assigned to this role!";

        var result = await _userManager.AddToRoleAsync(user, model.Role);

        return result.Succeeded ? string.Empty : "something went wrong!";
    }

    public async Task<AuthModel> RefreshTokenAsync(string token)
    {
        var authModel = new AuthModel();

        var user = await _userManager.Users
            .SingleOrDefaultAsync(x => x.RefreshTokens.Any(t => t.Token == token));
        if (user is null)
        {
            authModel.Message = "Invalid token";
            return authModel;
        }

        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);
        if (!refreshToken.IsActive)
        {
            authModel.Message = "Inactive token";
            return authModel;
        }

        refreshToken.RevokedOn = DateTime.UtcNow;
        var newRefreshToken = GenerateRefreshToken();

        user.RefreshTokens.Add(newRefreshToken);
        await _userManager.UpdateAsync(user);

        var jwtToken = await GenerateJwtTokenAsync(user);
        authModel.IsAuthenticated = true;
        authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
        authModel.Email = user.Email!;
        authModel.Username = user.UserName!;

        var rolesList = await _userManager.GetRolesAsync(user);
        authModel.Roles = rolesList.ToList();

        authModel.RefreshToken = newRefreshToken.Token;
        authModel.RefreshTokenExpiration = newRefreshToken.ExpiresOn;


        return authModel;
    }

    public async Task<bool> RevokeTokenAsync(string token)
    {
        var authModel = new AuthModel();

        var user = await _userManager.Users
            .SingleOrDefaultAsync(x => x.RefreshTokens.Any(t => t.Token == token));
        if (user is null)
            return false;

        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);
        if (!refreshToken.IsActive)
            return false;

        refreshToken.RevokedOn = DateTime.UtcNow;

        await _userManager.UpdateAsync(user);

        return true;
    }


    private async Task<JwtSecurityToken> GenerateJwtTokenAsync(ApplicationUser user)
    {
        var userClaims = await _userManager.GetClaimsAsync(user);

        var roles = await _userManager.GetRolesAsync(user);
        var roleClaims = roles.Select(role => new Claim("roles", role)).ToList();

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email!),
            new Claim("uid", user.Id)
        }.Union(userClaims).Union(roleClaims);

        var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
        var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

        var jwtSecurityToken = new JwtSecurityToken(
            issuer: _jwt.Issuer,
            audience: _jwt.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
            signingCredentials: signingCredentials
        );

        return jwtSecurityToken;
    }

    private RefreshToken GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);

        return new RefreshToken
        {
            Token = Convert.ToBase64String(randomNumber),
            ExpiresOn = DateTime.UtcNow.AddDays(10),
            CreatedOn = DateTime.UtcNow
        };
    }
}
