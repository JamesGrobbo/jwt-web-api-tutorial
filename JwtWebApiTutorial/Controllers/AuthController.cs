using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApiTutorial.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            //string userName = User?.Identity?.Name;
            var userName2 = User.FindFirstValue(ClaimTypes.Name);
            var role = User.FindFirstValue(ClaimTypes.Role);

            var userName = _userService.GetMyName();

            return Ok(new { userName, userName2, role });
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register (UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task <ActionResult<string>> Login(UserDto request)
        {
            if(user.Username != request.Username)
            {
                return BadRequest("User not found.");
            }

            if(!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Incorrect password.");
            }

            string token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                // add nameIdentifier claim (for user ID in db)
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            //var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
            //    _configuration.GetSection("AppSettings:Token").Value));

            // Get the AppSettings:Token value
            string appSettingsToken = _configuration.GetSection("AppSettings:Token").Value;

            // Hash the token value using SHA-512
            byte[] hashedTokenBytes;
            using (var sha512 = SHA512.Create())
            {
                hashedTokenBytes = sha512.ComputeHash(System.Text.Encoding.UTF8.GetBytes(appSettingsToken));
            }

            // Use the hashed token bytes to create a SymmetricSecurityKey
            var key = new SymmetricSecurityKey(hashedTokenBytes);

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
