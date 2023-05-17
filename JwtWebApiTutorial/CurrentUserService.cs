using Microsoft.AspNetCore.Mvc;

namespace JwtWebApiTutorial
{
    //public class CurrentUserService
    //{
    //    private IHttpContextAccessor _httpContextAccessor;

    //    public CurrentUserService(IHttpContextAccessor httpContextAccessor)
    //    {
    //        _httpContextAccessor = httpContextAccessor;
    //    }

    //    public string UserName => _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
    //    public ActionResult<string> GetMe()
    //    {
    //        string userName = User?.Identity?.Name;
    //        var userName2 = User.FindFirstValue(ClaimTypes.Name);
    //        var role = User.FindFirstValue(ClaimTypes.Role);
    //        return Ok(new { userName, userName2, role });
    //    }
    //}
}
