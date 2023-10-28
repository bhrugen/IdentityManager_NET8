using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class AccessCheckerController : Controller
    {
        //Anyone can access this
        public IActionResult AllAccess()
        {
            return View();
        }


        //Anyone that has logged in can access
        public IActionResult AuthorizedAccess()
        {
            return View();
        }


        //account with role of user can access
        public IActionResult UserRoleAccess()
        {
            return View();
        }


        //account with role of admin can access
        public IActionResult AdminRoleAccess()
        {
            return View();
        }

        //account with admin role and create Claim can access
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }

        //account with admin role and (create & Edit & Delete) Claim can access (AND NOT OR)
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }


    }
}
