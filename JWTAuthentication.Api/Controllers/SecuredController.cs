using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class SecuredController : ControllerBase
{
    [HttpGet("[action]")]
    public IActionResult GetData()
    {
        return Ok("Hello from secured controller");
    }
}
