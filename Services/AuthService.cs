using static SafeVault.Helpers.ValidationHelpers;
using Microsoft.Data.Sqlite;
using SafeVault.Models;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
namespace SafeVault.Services
{
	public class AuthService
	{
		private readonly string _connectionString;
		private readonly IConfiguration _configuration;	
		public AuthService(IConfiguration configuration)
		{
			_configuration = configuration;
			_connectionString = $"Data Source={Path.Combine(AppContext.BaseDirectory, configuration["SafeValueDatabase"]!)}";
		}
		internal AuthService(string connectionString)
		{
			_connectionString = connectionString;
		}
		
		public string GenerateJwtToken(User user)
		{
			var claims = new []
			{
				new Claim(JwtRegisteredClaimNames.Sub, user.Username),
				new Claim(JwtRegisteredClaimNames.Email, user.Email),
				new Claim("role", user.Role),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
			};

			var jwtSection = _configuration.GetSection("Jwt");	

			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSection["Key"]!));
			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			var token = new JwtSecurityToken(
				issuer: jwtSection["Issuer"],
				audience: jwtSection["Audience"],
				claims: claims,
				expires: DateTime.Now.AddMinutes(30),
				signingCredentials: creds
			);

			return new JwtSecurityTokenHandler().WriteToken(token);
		}

		public bool LoginUser(string username, string password)
		{
			string allowedSpecialCharactersForPassword = "!@#$%^&*";

			if (!IsValidInput(username))
			{
				return false;
			}

			if (!IsValidInput(password, allowedSpecialCharactersForPassword))
			{
				return false;
			}

			string query = "SELECT COUNT(1) FROM Users WHERE Username = @username AND Password = @password";

			using (var connection = new SqliteConnection(_connectionString))
			{
				connection.Open();
				using (var command = connection.CreateCommand())
				{
					command.CommandText = query;
					command.Parameters.AddWithValue("@username", username);
					command.Parameters.AddWithValue("@password", password);
					var result = command.ExecuteScalar();
					int count = Convert.ToInt32(result);
					return count == 1;
				}
			}
		}
	}
}
