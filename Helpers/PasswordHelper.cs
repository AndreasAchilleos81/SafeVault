//using BCrypt.Net;	
namespace SafeVault.Helpers
{
	public static class PasswordHelper
	{
		public static string ConvertToHash(string password)
		{
			return BCrypt.Net.BCrypt.HashPassword(password);
		}

		public static bool VerifyPassword(string password, string hashedPassword)
		{
			return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
		}
	}
}
