using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.ViewModels
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Gender is required")]
        public string Gender { get; set; } = string.Empty;

        [Required(ErrorMessage = "NRIC is required")]
        [RegularExpression(@"^[STFG]\d{7}[A-Z]$", ErrorMessage = "Invalid NRIC format (e.g., S1234567A)")]
        public string NRIC { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+\-=\[\]{};':""\\|,.<>\/])[A-Za-z\d@$!%*?&#^()_+\-=\[\]{};':""\\|,.<>\/]{12,}$",
            ErrorMessage = "Password must be at least 12 characters and contain uppercase, lowercase, number, and special character")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm your password")]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Passwords do not match")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Date of birth is required")]
        [DataType(DataType.Date)]
        [Display(Name = "Date of Birth")]
        public DateTime DateOfBirth { get; set; }

        [Required(ErrorMessage = "Resume is required")]
        [Display(Name = "Resume (.docx or .pdf)")]
        public IFormFile? Resume { get; set; }

        [Required(ErrorMessage = "Please tell us about yourself")]
        [DataType(DataType.MultilineText)]
        [Display(Name = "Who Am I")]
        [StringLength(1000, ErrorMessage = "Description cannot exceed 1000 characters")]
        public string WhoAmI { get; set; } = string.Empty;

        public string RecaptchaToken { get; set; } = string.Empty;
    }
}
