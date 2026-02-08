using AceJobAgency.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;

namespace AceJobAgency.Controllers
{
    public class HomeController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IDataProtectionProvider _dataProtectionProvider;

        public HomeController(AppDbContext context, IDataProtectionProvider dataProtectionProvider)
        {
            _context = context;
            _dataProtectionProvider = dataProtectionProvider;
        }

        public async Task<IActionResult> Index()
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            var sessionId = HttpContext.Session.GetString("SessionId");
            
            if (string.IsNullOrEmpty(userEmail))
            {
                return RedirectToAction("Login", "Account");
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
            
            if (user == null)
            {
                HttpContext.Session.Clear();
                return RedirectToAction("Login", "Account");
            }

            // Check for multiple login detection
            if (!string.IsNullOrEmpty(sessionId) && user.CurrentSessionId != sessionId)
            {
                HttpContext.Session.Clear();
                TempData["ErrorMessage"] = "You have been logged out because you logged in from another device.";
                return RedirectToAction("Login", "Account");
            }

            // Check session timeout
            var loginTimeStr = HttpContext.Session.GetString("LoginTime");
            if (!string.IsNullOrEmpty(loginTimeStr))
            {
                var loginTime = DateTime.Parse(loginTimeStr);
                if ((DateTime.UtcNow - loginTime).TotalMinutes > 20)
                {
                    HttpContext.Session.Clear();
                    TempData["ErrorMessage"] = "Your session has expired. Please login again.";
                    return RedirectToAction("Login", "Account");
                }
            }

            // Decrypt NRIC for display
            try
            {
                var protector = _dataProtectionProvider.CreateProtector("AceJobAgency.NRIC.Protection");
                ViewBag.DecryptedNRIC = protector.Unprotect(user.NRIC);
            }
            catch
            {
                ViewBag.DecryptedNRIC = "[Decryption Error]";
            }

            return View(user);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error(int? statusCode = null)
        {
            var model = new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                StatusCode = statusCode ?? 500
            };

            if (statusCode.HasValue)
            {
                switch (statusCode.Value)
                {
                    case 404:
                        model.ErrorMessage = "The page you are looking for could not be found.";
                        break;
                    case 403:
                        model.ErrorMessage = "Access forbidden. You don't have permission to access this resource.";
                        break;
                    case 500:
                        model.ErrorMessage = "An internal server error occurred. Please try again later.";
                        break;
                    default:
                        model.ErrorMessage = "An error occurred while processing your request.";
                        break;
                }
            }

            return View(model);
        }
    }
}
