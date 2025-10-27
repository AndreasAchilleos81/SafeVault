using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SafeVault.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class UserController : ControllerBase
	{
		[Authorize(Roles = "User")]
		[HttpGet("dashboard")]
		public IActionResult GetUserData()
		{
			// Logic to retrieve user dashboard data
			return Ok(new { Message = "Welcome to the User Dashboard" });
		}
	}
}
