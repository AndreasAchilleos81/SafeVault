using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Database;
using SafeVault.Helpers;
using SafeVault.Models;
using static SafeVault.Helpers.PasswordHelper;

namespace SafeVault.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class AuthController : ControllerBase
	{
		private readonly SafeVaultDbContext _safeVaultDbContext;
		private readonly Services.UserService _userService;
		private readonly Services.AuthService _authService;

		public AuthController(Services.UserService userService, Services.AuthService authService, SafeVaultDbContext safeVaultDbContext)
		{
			_safeVaultDbContext = safeVaultDbContext;
			_userService = userService;
			_authService = authService;
		}

		[HttpPost("login")]
		public IActionResult Login([FromBody] LoginRequest request)
		{
			var user = _userService.ValidateUser(request.Email, request.Password);

			if (user == null || !VerifyPassword(request.Password, user.Password))
			{
				return Unauthorized();
			}

			var token = _authService.GenerateJwtToken(user);
			return Ok(new { Token = token });
		}

		[HttpPost("register")]
		public IActionResult Register([FromBody] LoginRequest request)
		{
			if (_safeVaultDbContext.Users.Any(u => u.Email == request.Email))
				return BadRequest("Username already exists.");

			var user = new User
			{
				Email = request.Email,
				PasswordHash = ConvertToHash(request.Password)
			};

			_safeVaultDbContext.Users.Add(user);
			_safeVaultDbContext.SaveChanges();

			return Ok("User registered successfully.");
		}
	}
}
