using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace SafeVault.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class AuthController : ControllerBase
	{
		private readonly Services.UserService _userService;
		private readonly Services.AuthService _authService;

		public AuthController(Services.UserService userService, Services.AuthService authService)
		{
			_userService = userService;
			_authService = authService;
		}

		[HttpPost("login")]
		public IActionResult Login([FromBody] LoginRequest request)
		{
			var user = _userService.ValidateCredential(request.Email, request.Password);
			if (user == null)
			{
				return Unauthorized();
			}

			var token = _authService.GenerateJwtToken(user);
			return Ok(new { Token = token });
		}
	}
}
