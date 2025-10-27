using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Database;
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

			if (user == null || !VerifyPassword(request.Password, user.PasswordHash))
			{
				return Unauthorized();
			}

			var token = _authService.GenerateJwtToken(user);
			return Ok(new { Token = token });
		}

		[HttpPost("register")]
		public IActionResult Register([FromBody] User user)
		{
			if (_safeVaultDbContext.Users.Any(u => u.Email == user.Email))
				return BadRequest("Email already exists.");

			var newUser = new User
			{
				Email = user.Email,
				Password = user.Password,
				Role = user.Role,
				Username = user.Username,
				PasswordHash = ConvertToHash(user.Password)
			};

			_safeVaultDbContext.Users.Add(newUser);
			_safeVaultDbContext.SaveChanges();

			return Ok("User registered successfully.");
		}
	}
}
