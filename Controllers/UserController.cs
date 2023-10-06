using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using loginAndReg.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;

namespace loginAndReg.Controllers;

public class UserController : Controller
{
    private readonly ILogger<UserController> _logger;
    private MyContext _context;


    public UserController(ILogger<UserController> logger, MyContext context)
    {
        _logger = logger;
        _context = context;
    }

    [HttpGet("")]
    public IActionResult Index()
    {

        return View();
    }

    // REGISTER
    [HttpPost("user/create")]
    public IActionResult CreateUser(User newUser)
    {
        if (!ModelState.IsValid)
        {
            return View("Index");

        }
        PasswordHasher<User> hasher = new();
        newUser.Password = hasher.HashPassword(newUser, newUser.Password);
        _context.Add(newUser);
        _context.SaveChanges();
        HttpContext.Session.SetInt32("UserId", newUser.UserId);
        return RedirectToAction("Success");
    }

    // LOGIN
    [HttpPost("user/login")]
    public IActionResult LoginUser(LogUser LogAttempt)
    {
        if (!ModelState.IsValid)
        {
            return View("Index");
        }
        User? dbUser = _context.Users.FirstOrDefault(t => t.Email == LogAttempt.LogEmail);
        if (dbUser == null)
        {
            ModelState.AddModelError("LogPassword", "Invalid Credentials");
            return View("Index");
        }
        PasswordHasher<LogUser> hasher = new();
        PasswordVerificationResult pwCompareResult = hasher.VerifyHashedPassword(LogAttempt, dbUser.Password, LogAttempt.LogPassword);
        if (pwCompareResult == 0)
        {
            ModelState.AddModelError("LogPassword", "Invalid Credentials");
            return View("Index");
        }
        HttpContext.Session.SetInt32("UserId", dbUser.UserId);

        return View("Success");
    }

    [SessionCheck]
    [HttpGet("success")]
    public IActionResult Success()
    {
        return View("Success");
    }

    [HttpPost("user/logout")]
    public RedirectToActionResult LogOut()
    {
        HttpContext.Session.Remove("UserId");
        return RedirectToAction("Index");
    }




    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

// Name this anything you want with the word "Attribute" at the end
public class SessionCheckAttribute : ActionFilterAttribute
{
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        // Find the session, but remember it may be null so we need int?
        int? userId = context.HttpContext.Session.GetInt32("UserId");
        // Check to see if we got back null
        if (userId == null)
        {
            // Redirect to the Index page if there was nothing in session
            // "Home" here is referring to "HomeController", you can use any controller that is appropriate here
            context.Result = new RedirectToActionResult("Index", "User", null);
        }
    }
}


