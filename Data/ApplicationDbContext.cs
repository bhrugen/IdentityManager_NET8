using IdentityManager.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityManager.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions options)
            : base(options)
        {
        }

        // Add a DbSet for each entity type that you want to include in your model. For more information
        public DbSet<ApplicationUser> ApplicationUser { get; set; }
    }
}
