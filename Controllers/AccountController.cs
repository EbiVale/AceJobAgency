using AceJobAgency.Models;
using AceJobAgency.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Controllers
{
    public class AccountController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _environment;
        private readonly IConfiguration _configuration;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AccountController(
            AppDbContext context, 
            IWebHostEnvironment environment,
            IConfiguration configuration,
            IDataProtectionProvider dataProtectionProvider,
            IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _environment = environment;
            _configuration = configuration;
            _dataProtectionProvider = dataProtectionProvider;
            _httpContextAccessor = httpContextAccessor;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            // --- reCAPTCHA Verification ---
            var recaptchaResponse = model.RecaptchaToken;
            var secretKey = _configuration["RecaptchaSettings:SecretKey"];

            if (string.IsNullOrEmpty(recaptchaResponse))
            {
                ModelState.AddModelError("", "Please complete the reCAPTCHA verification.");
                return View(model);
            }

            using (var client = new HttpClient())
            {
                var response = await client.GetStringAsync(
                    $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={recaptchaResponse}");
                
                var captchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(response);

                if (captchaResult == null || !captchaResult.success || captchaResult.score < 0.5)
                {
                    ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                    return View(model);
                }
            }

            if (ModelState.IsValid)
            {
                // Check for duplicate email
                if (await _context.Users.AnyAsync(u => u.Email == model.Email))
                {
                    ModelState.AddModelError("Email", "Email already in use.");
                    return View(model);
                }

                // Handle file upload
                string? uniqueFileName = null;
                if (model.Resume != null)
                {
                    var allowedExtensions = new[] { ".docx", ".pdf" };
                    var fileExtension = Path.GetExtension(model.Resume.FileName).ToLowerInvariant();

                    if (!allowedExtensions.Contains(fileExtension))
                    {
                        ModelState.AddModelError("Resume", "Only .docx or .pdf files are allowed.");
                        return View(model);
                    }

                    // Additional file validation
                    if (model.Resume.Length > 5 * 1024 * 1024) // 5MB limit
                    {
                        ModelState.AddModelError("Resume", "File size must be less than 5MB.");
                        return View(model);
                    }

                    string uploadsFolder = Path.Combine(_environment.WebRootPath, "resumes");
                    uniqueFileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(model.Resume.FileName);
                    string filePath = Path.Combine(uploadsFolder, uniqueFileName);
                    
                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        await model.Resume.CopyToAsync(fileStream);
                    }
                }

                var passwordHasher = new PasswordHasher<ApplicationUser>();
                var user = new ApplicationUser
                {
                    FirstName = SanitizeInput(model.FirstName),
                    LastName = SanitizeInput(model.LastName),
                    Gender = model.Gender,
                    Email = model.Email.ToLowerInvariant(),
                    DateOfBirth = model.DateOfBirth,
                    ResumeFilePath = "/resumes/" + uniqueFileName,
                    WhoAmI = System.Net.WebUtility.HtmlEncode(model.WhoAmI),
                    NRIC = ProtectData(model.NRIC),
                    LastPasswordChangeDate = DateTime.UtcNow
                };

                user.PasswordHash = passwordHasher.HashPassword(user, model.Password);

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                // Audit log
                await LogActivity(user.Email, "Registration", GetClientIpAddress());

                TempData["SuccessMessage"] = "Registration successful! Please login.";
                return RedirectToAction("Login");
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult Login()
        {
            // Check if already logged in
            if (HttpContext.Session.GetString("UserEmail") != null)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string email, string password, string? twoFactorCode)
        {
            // --- reCAPTCHA Verification ---
            var recaptchaResponse = Request.Form["RecaptchaToken"].ToString();
            var secretKey = _configuration["RecaptchaSettings:SecretKey"];

            using (var client = new HttpClient())
            {
                var response = await client.GetStringAsync(
                    $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={recaptchaResponse}");
                
                var captchaResult = JsonSerializer.Deserialize<RecaptchaResponse>(response);

                if (captchaResult == null || !captchaResult.success || captchaResult.score < 0.5)
                {
                    ModelState.AddModelError("", "reCAPTCHA verification failed.");
                    return View();
                }
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email.ToLowerInvariant());
            
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                await LogActivity(email, "Failed Login - User Not Found", GetClientIpAddress());
                return View();
            }

            // Check if account is locked
            if (user.IsLockedOut)
            {
                var remainingTime = (user.LockoutEnd!.Value - DateTime.UtcNow).TotalMinutes;
                ModelState.AddModelError("", $"Account is locked. Please try again in {Math.Ceiling(remainingTime)} minutes.");
                return View();
            }

            var hasher = new PasswordHasher<ApplicationUser>();
            var result = hasher.VerifyHashedPassword(user, user.PasswordHash, password);

            if (result == PasswordVerificationResult.Success)
            {
                // Check 2FA if enabled
                if (user.TwoFactorEnabled)
                {
                    if (string.IsNullOrEmpty(twoFactorCode))
                    {
                        // Show 2FA input
                        TempData["Require2FA"] = true;
                        TempData["UserEmail"] = email;
                        return View();
                    }
                    
                    // Verify 2FA code
                    if (!Verify2FACode(user, twoFactorCode))
                    {
                        ModelState.AddModelError("", "Invalid two-factor authentication code.");
                        return View();
                    }
                }

                // Reset failed login attempts
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;

                // Generate new session ID
                var sessionId = Guid.NewGuid().ToString();
                
                // Check for multiple logins
                if (!string.IsNullOrEmpty(user.CurrentSessionId))
                {
                    // User is already logged in from another device
                    TempData["WarningMessage"] = "You were logged out from another device.";
                }
                
                user.CurrentSessionId = sessionId;
                await _context.SaveChangesAsync();

                // Set session
                HttpContext.Session.SetString("UserEmail", user.Email);
                HttpContext.Session.SetString("UserId", user.Id.ToString());
                HttpContext.Session.SetString("SessionId", sessionId);
                HttpContext.Session.SetString("LoginTime", DateTime.UtcNow.ToString("o"));

                await LogActivity(user.Email, "Successful Login", GetClientIpAddress());

                return RedirectToAction("Index", "Home");
            }
            else
            {
                // Increment failed login attempts
                user.FailedLoginAttempts++;

                if (user.FailedLoginAttempts >= 3)
                {
                    // Lock account for 15 minutes
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(15);
                    ModelState.AddModelError("", "Account locked due to multiple failed login attempts. Please try again in 15 minutes.");
                }
                else
                {
                    ModelState.AddModelError("", $"Invalid login attempt. {3 - user.FailedLoginAttempts} attempts remaining.");
                }

                await _context.SaveChangesAsync();
                await LogActivity(email, "Failed Login - Invalid Password", GetClientIpAddress());
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            
            if (!string.IsNullOrEmpty(userEmail))
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
                if (user != null)
                {
                    user.CurrentSessionId = null;
                    await _context.SaveChangesAsync();
                }

                await LogActivity(userEmail, "Logout", GetClientIpAddress());
            }

            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
            {
                return RedirectToAction("Login");
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
            {
                return RedirectToAction("Login");
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // Verify current password
            var hasher = new PasswordHasher<ApplicationUser>();
            var result = hasher.VerifyHashedPassword(user, user.PasswordHash, model.CurrentPassword);

            if (result != PasswordVerificationResult.Success)
            {
                ModelState.AddModelError("", "Current password is incorrect.");
                return View(model);
            }

            // Check minimum password age
            if (user.LastPasswordChangeDate.HasValue)
            {
                var hoursSinceLastChange = (DateTime.UtcNow - user.LastPasswordChangeDate.Value).TotalHours;
                if (hoursSinceLastChange < 24)
                {
                    ModelState.AddModelError("", $"You cannot change your password yet. Please wait {Math.Ceiling(24 - hoursSinceLastChange)} more hours.");
                    return View(model);
                }
            }

            // Check password history
            var newPasswordHash = hasher.HashPassword(user, model.NewPassword);

            if (user.PreviousPasswordHash1 != null &&
                hasher.VerifyHashedPassword(user, user.PreviousPasswordHash1, model.NewPassword) == PasswordVerificationResult.Success)
            {
                ModelState.AddModelError("", "You cannot reuse your previous password.");
                return View(model);
            }

            if (user.PreviousPasswordHash2 != null &&
                hasher.VerifyHashedPassword(user, user.PreviousPasswordHash2, model.NewPassword) == PasswordVerificationResult.Success)
            {
                ModelState.AddModelError("", "You cannot reuse your previous password.");
                return View(model);
            }

            // Update password history
            user.PreviousPasswordHash2 = user.PreviousPasswordHash1;
            user.PreviousPasswordHash1 = user.PasswordHash;
            user.PasswordHash = newPasswordHash;
            user.LastPasswordChangeDate = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            await LogActivity(userEmail, "Password Changed", GetClientIpAddress());

            TempData["SuccessMessage"] = "Password changed successfully!";
            return RedirectToAction("Index", "Home");
        }

        // Helper Methods
        private string ProtectData(string clearText)
        {
            var protector = _dataProtectionProvider.CreateProtector("AceJobAgency.NRIC.Protection");
            return protector.Protect(clearText);
        }

        public string UnprotectData(string cipherText)
        {
            try
            {
                var protector = _dataProtectionProvider.CreateProtector("AceJobAgency.NRIC.Protection");
                return protector.Unprotect(cipherText);
            }
            catch
            {
                return "[Decryption Error]";
            }
        }

        private string SanitizeInput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;
            
            // Remove potentially dangerous characters
            return System.Net.WebUtility.HtmlEncode(input.Trim());
        }

        private string GetClientIpAddress()
        {
            var ipAddress = _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString();
            return ipAddress ?? "Unknown";
        }

        private async Task LogActivity(string userEmail, string activity, string? ipAddress = null)
        {
            var log = new AuditLog
            {
                UserEmail = userEmail,
                Activity = activity,
                Timestamp = DateTime.UtcNow,
                IpAddress = ipAddress
            };
            _context.AuditLogs.Add(log);
            await _context.SaveChangesAsync();
        }

        private bool Verify2FACode(ApplicationUser user, string code)
        {
            return !string.IsNullOrEmpty(code) && code.Length == 6;
        }
    }

    public class RecaptchaResponse
    {
        public bool success { get; set; }
        public double score { get; set; }
        public string action { get; set; } = string.Empty;
        public DateTime challenge_ts { get; set; }
        public string hostname { get; set; } = string.Empty;
    }
}
