using Microsoft.EntityFrameworkCore;
using SafeVault.Database;
using SafeVault.Models;

namespace SafeVault.Services
{
	public class UserService
	{
		private readonly SafeVaultDbContext _safeVaultDbContext;

		public UserService(SafeVaultDbContext safeVaultDbContext)
		{
			_safeVaultDbContext = safeVaultDbContext;
		}

		public User? ValidateUser(string email, string password)
		{
			return _safeVaultDbContext.
								Users.
								FromSqlInterpolated($"Select * FROM Users WHERE Email = {email} AND Password = {password} LIMIT 1").
								FirstOrDefault();
		}
	}
}
