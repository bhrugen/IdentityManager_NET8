using IdentityManager;
using IdentityManager.Authorize;
using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Services;
using IdentityManager.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using System.Drawing.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options=>
options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new PathString("/Account/NoAccess");
});
builder.Services.Configure<IdentityOptions>(opt =>
{
    opt.Password.RequireDigit = false;
    opt.Password.RequireLowercase = false;
    opt.Password.RequireNonAlphanumeric = false;
    opt.Lockout.MaxFailedAccessAttempts = 3;
    opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromDays(10000);
    opt.SignIn.RequireConfirmedEmail = false;
});
builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
    opt.AddPolicy("AdminAndUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
    opt.AddPolicy("AdminRole_CreateClaim", policy => policy.RequireRole(SD.Admin).RequireClaim("create","True"));
    opt.AddPolicy("AdminRole_CreateEditDeleteClaim", policy => policy
                    .RequireRole(SD.Admin)
                    .RequireClaim("create", "True")
                    .RequireClaim("edit", "True")
                    .RequireClaim("delete", "True")
                 );

opt.AddPolicy("AdminRole_CreateEditDeleteClaim_ORSuperAdminRole", policy => policy.RequireAssertion(context =>
    AdminRole_CreateEditDeleteClaim_ORSuperAdminRole(context)



    ));
    opt.AddPolicy("OnlySuperAdminChecker", p => p.Requirements.Add(new OnlySuperAdminChecker()));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();


bool AdminRole_CreateEditDeleteClaim_ORSuperAdminRole(AuthorizationHandlerContext context)
{
    return (
        context.User.IsInRole(SD.Admin) && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
        && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
        && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
    )
    || context.User.IsInRole(SD.SuperAdmin);
}