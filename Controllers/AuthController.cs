using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Identity.Data;
using Identity.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IConfiguration configuration,
    ApplicationDbContext context
) : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
    private readonly IConfiguration _configuration = configuration;
    private readonly ApplicationDbContext _context = context;

    public record RegisterRequest(string Username, string Email, string Password);
    public record LoginRequest(string Username, string Password);

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var user = new ApplicationUser { UserName = request.Username, Email = request.Email };
        var result = await _userManager.CreateAsync(user, request.Password);

        if (result.Succeeded)
        {
            return Ok(new { Message = "User registered successfully." });
        }

        return BadRequest(result.Errors.Select(e => e.Description));
    }

    [HttpPost("signin")]
    public async Task<IActionResult> SignIn(LoginRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username);
        if (user is null)
        {
            return Unauthorized();
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);

        if (!result.Succeeded)
        {
            return Unauthorized();
        }

        var accessToken = GenerateAccessToken(user);
        var refreshToken = GenerateRefreshToken();

        await _userManager.SetAuthenticationTokenAsync(
            user,
            _configuration["Jwt:Issuer"]!,
            "refresh_token",
            refreshToken
        );

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.Now.AddDays(7)
        };
        HttpContext.Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);

        return Ok(new { Message = "User signed in successfully.", accessToken });
    }

    [HttpGet]
    public IActionResult GetAuthenticationStatus()
    {
        var status = User.Identity?.IsAuthenticated ?? false;
        return Ok(new { IsAuthenticated = status });
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = HttpContext.Request.Cookies["refreshToken"];
        var userToken = await _context.UserTokens.FirstOrDefaultAsync(ut => ut.Value == refreshToken);

        if (userToken is null || userToken.LoginProvider != _configuration["Jwt:Issuer"] || userToken.Name != "refresh_token")
        {
            return Unauthorized();
        }

        var user = await _userManager.FindByIdAsync(userToken.UserId);

        if (user is null)
        {
            return Unauthorized();
        }

        var accessToken = GenerateAccessToken(user);
        var newRefreshToken = GenerateRefreshToken();

        await _userManager.SetAuthenticationTokenAsync(
            user,
            _configuration["Jwt:Issuer"]!,
            "refresh_token",
            newRefreshToken
        );

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.Now.AddDays(7)
        };
        HttpContext.Response.Cookies.Append("refreshToken", newRefreshToken, cookieOptions);

        return Ok(new { Message = "Refresh token successfully.", accessToken });
    }

    private string GenerateAccessToken(ApplicationUser user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            _configuration["Jwt:Issuer"],
            _configuration["Jwt:Audience"],
            claims,
            expires: DateTime.Now.AddMinutes(10),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);

        return Convert.ToBase64String(randomNumber);
    }
}