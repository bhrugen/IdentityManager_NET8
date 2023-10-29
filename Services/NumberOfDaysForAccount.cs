using IdentityManager.Data;
using IdentityManager.Services.IServices;

namespace IdentityManager.Services
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDbContext _db;
        public NumberOfDaysForAccount(ApplicationDbContext db)
        {
            _db = db;
        }
        public int Get(string userId)
        {
            var user = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if(user!=null && user.DateCreated != DateTime.MinValue)
            {
                return (DateTime.Today - user.DateCreated).Days;
            }
            return 0;
        }
    }
}
