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

		public User? ValidateCredential(string email, string password)
		{
			return _safeVaultDbContext.Users.FirstOrDefault(u => u.Email == email && u.Password == password);
		}
	}
}
