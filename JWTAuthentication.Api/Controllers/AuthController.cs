using JWTAuthentication.Api.Models;
using JWTAuthentication.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.Api.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController(IAuthService service) : ControllerBase
{
    private readonly IAuthService _service = service;


    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        var result = await _service.RegisterAsync(model);

        SetRefreshTokens(result.RefreshToken!, result.RefreshTokenExpiration);

        return result.IsAuthenticated ? Ok(result) : BadRequest(result.Message);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] TokenRequestModel model)
    {
        var result = await _service.GetTokenAsync(model);

        if (!string.IsNullOrEmpty(result.RefreshToken))
            SetRefreshTokens(result.RefreshToken, result.RefreshTokenExpiration);

        return result.IsAuthenticated ? Ok(result) : BadRequest(result.Message);
    }


    [HttpPost("addRole")]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult> AddRole([FromBody] AddRoleModel model)
    {
        var result = await _service.AddRoleAsync(model);

        return string.IsNullOrEmpty(result) ? Ok(model) : BadRequest(result);
    }


    [HttpGet("refreshToken")]
    public async Task<IActionResult> RefreshToken()
    {
        if (!Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
            return BadRequest("Invalid refresh token");

        var result = await _service.RefreshTokenAsync(refreshToken);

        if (!string.IsNullOrEmpty(result.RefreshToken))
            SetRefreshTokens(result.RefreshToken, result.RefreshTokenExpiration);

        return result.IsAuthenticated ? Ok(result) : BadRequest(result.Message);
    }


    [HttpPost("revokeToken")]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenModel model)
    {
        var token = model.Token ?? Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(token))
            return BadRequest("Invalid refresh token");

        var result = await _service.RevokeTokenAsync(token);

        return result ? Ok(result) : BadRequest("Token is invalid!");
    }


    private void SetRefreshTokens(string refreshToken, DateTime expires)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = expires.ToLocalTime()
        };

        Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
    }
}
