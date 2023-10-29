using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        //Anyone can access this
        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }

   
        //Anyone that has logged in can access
        public IActionResult AuthorizedAccess()
        {
            return View();
        }

        [Authorize(Roles = $"{SD.Admin},{SD.User}")]
        //account with role of user or admin can access
        public IActionResult UserORAdminRoleAccess()
        {
            return View();
        }

        [Authorize(Policy = "AdminAndUser")]
        //account with role of user or admin can access
        public IActionResult UserANDAdminRoleAccess()
        {
            return View();
        }

        [Authorize(Policy = "Admin")]
        //account with role of admin can access
        public IActionResult AdminRoleAccess()
        {
            return View();
        }

        [Authorize(Policy = "AdminRole_CreateClaim")]
        //account with admin role and create Claim can access
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }

        [Authorize(Policy = "AdminRole_CreateEditDeleteClaim")]
        //account with admin role and (create & Edit & Delete) Claim can access (AND NOT OR)
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }

        [Authorize(Policy = "AdminRole_CreateEditDeleteClaim_ORSuperAdminRole")]
        //account with admin role and (create & Edit & Delete) Claim can access (AND NOT OR)
        public IActionResult Admin_Create_Edit_DeleteAccess_OR_SuperAdminRole()
        {
            return View();
        }

        public IActionResult OnlyBhrugen()
        {
            return View();
        }
    }
}
