using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;
using SafeVault.Models;
using SafeVault.Services;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace SafeVault.tests
{
	[TestFixture]
	public class AuthTests
	{
		private HttpClient _client;
		private AuthService _authService;

		[SetUp]
		public void Setup()
		{
			var appFactory = new WebApplicationFactory<Program>()
				.WithWebHostBuilder(builder =>
				{
					builder.UseContentRoot("C:\\Users\\a.achilleos\\code\\SafeVault");
				});

			var configuration = new ConfigurationBuilder()
				.SetBasePath(Directory.GetCurrentDirectory())
				.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
				.Build();


			_client = appFactory.CreateClient();
			_authService = new AuthService(configuration); // new AuthService("Data Source=C:\\Users\\a.achilleos\\code\\SafeVault\\SafeVaultDb");
		}

		[Test]
		public async Task Login_WithInvalidCredentials_ShouldReturnUnauthorized()
		{
			var payload = new
			{
				Email = "nonexistent@email.com",
				Password = "wrongpass"
			};

			var response = await _client.PostAsJsonAsync("auth/login", payload);
			Assert.That(HttpStatusCode.Unauthorized == response.StatusCode, Is.True);
		}

		[Test]
		public async Task Login_WithValidCredentials_ShouldReturnJwtToken()
		{
			var payload = new
			{
				Email = "kokos@email.com",
				Password = "Password1"
			};

			var response = await _client.PostAsJsonAsync("auth/login", payload);
			Assert.That(HttpStatusCode.OK == response.StatusCode, Is.True);

			var json = await response.Content.ReadFromJsonAsync<JsonElement>();
			Assert.That(json.TryGetProperty("token", out _), Is.True);
		}

		[Test]
		public async Task Access_AdminRoute_WithoutToken_ShouldBeDenied()
		{
			var response = await _client.GetAsync("/admin/dashboard");
			Assert.That(HttpStatusCode.Unauthorized == response.StatusCode, Is.True);
		}


		[Test]
		public async Task Access_AdminRoute_WithUserToken_ShouldBeForbidden()
		{
			var user = new User()
			{
				Username = "kokos",
				Password = "Password1",
				Email = "kokos@email.com",
				Role = "User",
				PasswordHash = "$2a$11$aShEPPiw34dcXGXbX3S4J.yaG9JCvG3U3vw2kO9Vd25mErgqPWeyu"
			};

			var token = _authService.GenerateJwtToken(user);

			_client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
			var response = await _client.GetAsync("/admin/dashboard");

			Assert.That(HttpStatusCode.Forbidden == response.StatusCode, Is.True);
		}

		[Test]
		public async Task Access_AdminRoute_WithAdminToken_ShouldSucceed()
		{
			var user = new User()
			{
				Username = "kokos",
				Password = "Password1",
				Email = "kokos@email.com",
				Role = "Admin",
				PasswordHash = "$2a$11$aShEPPiw34dcXGXbX3S4J.yaG9JCvG3U3vw2kO9Vd25mErgqPWeyu"
			};

			var token = _authService.GenerateJwtToken(user);

			_client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
			var response = await _client.GetAsync("/admin/dashboard");

			Assert.That(HttpStatusCode.OK == response.StatusCode, Is.True);
		}


	}
}
