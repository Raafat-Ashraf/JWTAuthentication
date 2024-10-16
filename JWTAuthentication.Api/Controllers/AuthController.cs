using JWTAuthentication.Api.Models;
using JWTAuthentication.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

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

        return result.IsAuthenticated ? Ok(result) : BadRequest(result.Message);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Register([FromBody] TokenRequestModel model)
    {
        var result = await _service.GetTokenAsync(model);

        return result.IsAuthenticated ? Ok(result) : BadRequest(result.Message);
    }


    [HttpPost("addRole")]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult> AddRole([FromBody] AddRoleModel model)
    {
        var result = await _service.AddRoleAsync(model);

        return string.IsNullOrEmpty(result) ? Ok(model) : BadRequest(result);
    }
}
