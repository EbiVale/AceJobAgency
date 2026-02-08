using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models
{
    public class ApplicationUser
    {
        [Key]
        public int Id { get; set; }

        public string FirstName { get; set; } = string.Empty;

        public string LastName { get; set; } = string.Empty;

        public string Gender { get; set; } = string.Empty;

        public string NRIC { get; set; } = string.Empty;

        [Required]
        public string Email { get; set; } = string.Empty;

        public string PasswordHash { get; set; } = string.Empty;

        public DateTime DateOfBirth { get; set; }

        public string? ResumeFilePath { get; set; }

        public string WhoAmI { get; set; } = string.Empty;

        // Security Features
        public int FailedLoginAttempts { get; set; } = 0;
        
        public DateTime? LockoutEnd { get; set; }
        
        public bool IsLockedOut => LockoutEnd.HasValue && LockoutEnd.Value > DateTime.UtcNow;
        
        public string? PreviousPasswordHash1 { get; set; }
        
        public string? PreviousPasswordHash2 { get; set; }
        
        public DateTime? LastPasswordChangeDate { get; set; }
        
        public string? TwoFactorSecret { get; set; }
        
        public bool TwoFactorEnabled { get; set; } = false;

        public string? CurrentSessionId { get; set; }
    }
}
