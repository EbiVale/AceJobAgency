using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Models
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<ApplicationUser> Users { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
    }

    public class AuditLog
    {
        public int Id { get; set; }
        public string UserEmail { get; set; } = string.Empty;
        public string Activity { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string? IpAddress { get; set; }
    }
}
