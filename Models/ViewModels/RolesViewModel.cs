namespace IdentityManager.Models.ViewModels
{
    public class RolesViewModel
    {
        public RolesViewModel()
        {
            RolesList = [];
        }
        public ApplicationUser User { get; set; }
        public IEnumerable<RoleSelection> RolesList { get; set; }
    }


    public class RoleSelection
    {
        public string RoleName { get; set; }
        public bool IsSelected { get; set; }
    }
}
