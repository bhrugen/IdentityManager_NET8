namespace IdentityManager.Models.ViewModels
{
    public class ClaimsViewModel
    {
        public ClaimsViewModel()
        {
            ClaimList = [];
        }
        public ApplicationUser User { get; set; }
        public List<ClaimSelection> ClaimList { get; set; }
    }


    public class ClaimSelection
    {
        public string ClaimType { get; set; }
        public bool IsSelected { get; set; }
    }
}
