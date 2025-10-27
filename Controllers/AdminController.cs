using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace SafeVault.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class AdminController : ControllerBase
	{
		[Authorize(Roles = "Admin")]
		[HttpGet("dashboard")]
		public IActionResult GetDashboard()
		{
			// Logic to retrieve admin dashboard data
			return Ok(new { Message = "Welcome to the Admin Dashboard" });
		}
	}
}
