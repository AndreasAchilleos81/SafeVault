using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Database;
using SafeVault.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, builder.Configuration["SafeValueDatabase"]));
builder.Services.AddDbContext<SafeVaultDbContext>(options => 
{
	options.UseSqlite("Data Source=" + path);
});

builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<AuthService>();
var  jwtSection = builder.Configuration.GetSection("Jwt");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
	.AddJwtBearer(options =>
	{
		options.TokenValidationParameters = new TokenValidationParameters
		{
			ValidateIssuer = true,
			ValidateAudience = true,
			ValidateLifetime = true,
			ValidateIssuerSigningKey = true,
			ValidIssuer = jwtSection["Issuer"],
			ValidAudience = jwtSection["Audience"],
			IssuerSigningKey = new SymmetricSecurityKey(
				Encoding.UTF8.GetBytes(jwtSection["Key"]))
		};

		options.Events = new JwtBearerEvents
		{
			OnAuthenticationFailed = context =>
			{
				Console.WriteLine("OnAuthenticationFailed: " + context.Exception.Message);
				return Task.CompletedTask;
			},
			OnTokenValidated = context =>
			{
				Console.WriteLine("OnTokenValidated: " + context.SecurityToken);
				return Task.CompletedTask;
			}
		};

	});
builder.Services.AddAuthorization(options =>
{
	options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
	var dbContext = scope.ServiceProvider.GetRequiredService<SafeVaultDbContext>();
	dbContext.Database.EnsureCreated();
}
app.UseHttpsRedirection();

app.MapGet("/", () => "This is root!!!");
app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();
app.MapControllerRoute(
	name: "default",
	pattern: "{controller=Home}/{action=Index}/{id?}");	

app.MapControllers();
app.Run();

