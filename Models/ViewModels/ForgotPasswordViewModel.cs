using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        
    }
}
