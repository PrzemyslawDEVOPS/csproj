using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;

// ==========================================
// 1. LOGIKA STARTOWA
// ==========================================

var builder = WebApplication.CreateBuilder(args);

// Baza danych In-Memory
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseInMemoryDatabase("BeFitDb"));

// Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.AddControllersWithViews();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
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

// Inicjalizacja danych - tworzenie roli Admin i użytkownika administratora
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    
    // Utwórz rolę Admin, jeśli nie istnieje
    if (!await roleManager.RoleExistsAsync("Admin"))
    {
        await roleManager.CreateAsync(new IdentityRole("Admin"));
    }
    
    // Utwórz użytkownika administratora, jeśli nie istnieje
    var adminEmail = "admin@befit.pl";
    var adminPassword = "Admin123!";
    
    var adminUser = await userManager.FindByEmailAsync(adminEmail);
    if (adminUser == null)
    {
        adminUser = new IdentityUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            EmailConfirmed = true
        };
        
        var result = await userManager.CreateAsync(adminUser, adminPassword);
        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(adminUser, "Admin");
        }
    }
    else if (!await userManager.IsInRoleAsync(adminUser, "Admin"))
    {
        await userManager.AddToRoleAsync(adminUser, "Admin");
    }
}

app.Run();

// ==========================================
// 2. DEFINICJE KLAS (MODELE I KONTROLERY)
// ==========================================

// --- DATABASE ---
public class ApplicationDbContext : IdentityDbContext<IdentityUser, IdentityRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    { }

    public DbSet<Exercise> Exercises { get; set; }
    public DbSet<WorkoutSession> WorkoutSessions { get; set; }
    public DbSet<WorkoutSessionDetail> WorkoutSessionDetails { get; set; }
}

// --- ENTITIES (Poprawione nulle "?") ---

public class Exercise
{
    [Key]
    public int ExerciseId { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 2)]
    [Display(Name = "Nazwa ćwiczenia")]
    public string? Name { get; set; }
}

public class WorkoutSession
{
    [Key]
    public int WorkoutSessionId { get; set; }

    [Required]
    public string? UserId { get; set; }

    [Required]
    [DataType(DataType.DateTime)]
    [Display(Name = "Data i godzina rozpoczęcia")]
    public DateTime StartTime { get; set; }

    [Required]
    [DataType(DataType.DateTime)]
    [Display(Name = "Data i godzina zakończenia")]
    [CustomValidation(typeof(WorkoutSession), nameof(ValidateEndTime))]
    public DateTime EndTime { get; set; }

    [ForeignKey("UserId")]
    public IdentityUser? User { get; set; } // Dodano '?'

    public static ValidationResult? ValidateEndTime(DateTime endTime, ValidationContext context)
    {
        var instance = context.ObjectInstance as WorkoutSession;
        if (instance != null && instance.StartTime >= endTime)
        {
            return new ValidationResult("End time must be after start time.");
        }
        return ValidationResult.Success;
    }
}

public class WorkoutSessionDetail
{
    [Key]
    public int WorkoutSessionDetailId { get; set; }

    [Required]
    [Display(Name = "Sesja treningowa")]
    public int WorkoutSessionId { get; set; }
    [ForeignKey("WorkoutSessionId")]
    public WorkoutSession? WorkoutSession { get; set; }

    [Required]
    [Display(Name = "Ćwiczenie")]
    public int ExerciseId { get; set; }
    [ForeignKey("ExerciseId")]
    public Exercise? Exercise { get; set; }

    [Required]
    [StringLength(450)]
    public string? UserId { get; set; }
    [ForeignKey("UserId")]
    public IdentityUser? User { get; set; }

    [Required]
    [Range(1, 1000)]
    [Display(Name = "Liczba serii")]
    public int Sets { get; set; }

    [Required]
    [Range(1, 10000)]
    [Display(Name = "Liczba powtórzeń w serii")]
    public int Repetitions { get; set; }

    [Required]
    [Range(0, 1000)]
    [Display(Name = "Obciążenie (kg)")]
    public decimal Weight { get; set; }
}

// --- VIEW MODELS ---

public class RegisterViewModel
{
    [Required]
    [EmailAddress]
    public string? Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 6)]
    public string? Password { get; set; }

    [DataType(DataType.Password)]
    [Compare("Password")]
    public string? ConfirmPassword { get; set; }
}

public class LoginViewModel
{
    [Required]
    [EmailAddress]
    public string? Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public string? Password { get; set; }

    public bool RememberMe { get; set; }
}

// --- CONTROLLERS ---

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}

[AllowAnonymous]
public class ExerciseController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;

    public ExerciseController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    [AllowAnonymous]
    public async Task<IActionResult> Index()
    {
        return View(await _context.Exercises.ToListAsync());
    }

    [AllowAnonymous]
    public async Task<IActionResult> Details(int? id)
    {
        if (id == null) return NotFound();
        var exercise = await _context.Exercises.FirstOrDefaultAsync(e => e.ExerciseId == id);
        if (exercise == null) return NotFound();
        return View(exercise);
    }

    [Authorize(Roles = "Admin")]
    public IActionResult Create()
    {
        return View();
    }

    [HttpPost]
    [Authorize(Roles = "Admin")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create([Bind("Name")] Exercise exercise)
    {
        if (ModelState.IsValid)
        {
            _context.Add(exercise);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
        return View(exercise);
    }

    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Edit(int? id)
    {
        if (id == null) return NotFound();
        var exercise = await _context.Exercises.FindAsync(id);
        if (exercise == null) return NotFound();
        return View(exercise);
    }

    [HttpPost]
    [Authorize(Roles = "Admin")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, [Bind("ExerciseId,Name")] Exercise exercise)
    {
        if (id != exercise.ExerciseId) return NotFound();
        if (ModelState.IsValid)
        {
            try
            {
                _context.Update(exercise);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!_context.Exercises.Any(e => e.ExerciseId == id))
                    return NotFound();
                throw;
            }
            return RedirectToAction(nameof(Index));
        }
        return View(exercise);
    }

    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> Delete(int? id)
    {
        if (id == null) return NotFound();
        var exercise = await _context.Exercises.FirstOrDefaultAsync(e => e.ExerciseId == id);
        if (exercise == null) return NotFound();
        return View(exercise);
    }

    [HttpPost, ActionName("Delete")]
    [Authorize(Roles = "Admin")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        var exercise = await _context.Exercises.FindAsync(id);
        if (exercise != null)
        {
            _context.Exercises.Remove(exercise);
            await _context.SaveChangesAsync();
        }
        return RedirectToAction(nameof(Index));
    }
}

[Authorize]
public class WorkoutSessionController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;

    public WorkoutSessionController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    public async Task<IActionResult> Index()
    {
        string? userId = _userManager.GetUserId(User);
        if (userId == null) return Forbid();

        var sessions = await _context.WorkoutSessions
            .Where(w => w.UserId == userId)
            .ToListAsync();
        return View(sessions);
    }

    public async Task<IActionResult> Details(int? id)
    {
        if (id == null) return NotFound();
        var ws = await _context.WorkoutSessions
            .FirstOrDefaultAsync(m => m.WorkoutSessionId == id && m.UserId == _userManager.GetUserId(User));
        if (ws == null) return NotFound();
        return View(ws);
    }

    public IActionResult Create()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create([Bind("StartTime,EndTime")] WorkoutSession workoutSession)
    {
        // Ustaw UserId przed walidacją
        workoutSession.UserId = _userManager.GetUserId(User);
        
        // Usuń błąd walidacji dla UserId, ponieważ jest ustawiane automatycznie
        ModelState.Remove(nameof(workoutSession.UserId));
        
        if (ModelState.IsValid)
        {
            _context.Add(workoutSession);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
        return View(workoutSession);
    }

    public async Task<IActionResult> Edit(int? id)
    {
        if (id == null) return NotFound();
        var ws = await _context.WorkoutSessions.FindAsync(id);
        if (ws == null || ws.UserId != _userManager.GetUserId(User))
            return Forbid();
        return View(ws);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, [Bind("WorkoutSessionId,StartTime,EndTime")] WorkoutSession workoutSession)
    {
        if (id != workoutSession.WorkoutSessionId)
            return NotFound();

        string? userId = _userManager.GetUserId(User);
        var ws = await _context.WorkoutSessions.AsNoTracking().FirstOrDefaultAsync(w => w.WorkoutSessionId == id && w.UserId == userId);
        if (ws == null)
            return Forbid();

        // Ustaw UserId przed walidacją
        workoutSession.UserId = userId;
        
        // Usuń błąd walidacji dla UserId, ponieważ jest ustawiane automatycznie
        ModelState.Remove(nameof(workoutSession.UserId));

        if (ModelState.IsValid)
        {
            try
            {
                _context.Update(workoutSession);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!_context.WorkoutSessions.Any(w => w.WorkoutSessionId == id && w.UserId == workoutSession.UserId))
                    return NotFound();
                throw;
            }
            return RedirectToAction(nameof(Index));
        }
        return View(workoutSession);
    }

    public async Task<IActionResult> Delete(int? id)
    {
        if (id == null) return NotFound();
        var ws = await _context.WorkoutSessions
            .FirstOrDefaultAsync(w => w.WorkoutSessionId == id && w.UserId == _userManager.GetUserId(User));
        if (ws == null) return Forbid();
        return View(ws);
    }

    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        var ws = await _context.WorkoutSessions
            .FirstOrDefaultAsync(w => w.WorkoutSessionId == id && w.UserId == _userManager.GetUserId(User));
        if (ws == null) return Forbid();
        _context.WorkoutSessions.Remove(ws);
        await _context.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }
}

[Authorize]
public class WorkoutSessionDetailController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;

    public WorkoutSessionDetailController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    public async Task<IActionResult> Index()
    {
        string? userId = _userManager.GetUserId(User);
        if (userId == null) return Forbid();

        var details = await _context.WorkoutSessionDetails
            .Include(w => w.Exercise)
            .Include(w => w.WorkoutSession)
            .Where(w => w.UserId == userId)
            .ToListAsync();
        return View(details);
    }

    public async Task<IActionResult> Details(int? id)
    {
        if (id == null) return NotFound();
        string? userId = _userManager.GetUserId(User);

        var detail = await _context.WorkoutSessionDetails
            .Include(w => w.WorkoutSession)
            .Include(w => w.Exercise)
            .FirstOrDefaultAsync(w => w.WorkoutSessionDetailId == id && w.UserId == userId);
        if (detail == null) return Forbid();
        return View(detail);
    }

    public IActionResult Create()
    {
        string? userId = _userManager.GetUserId(User);
        ViewData["ExerciseId"] = new SelectList(_context.Exercises, "ExerciseId", "Name");
        ViewData["WorkoutSessionId"] = new SelectList(
            _context.WorkoutSessions
                .Where(w => w.UserId == userId)
                .Select(w => new { 
                    w.WorkoutSessionId, 
                    DisplayText = $"{w.StartTime:dd.MM.yyyy HH:mm} - {w.EndTime:dd.MM.yyyy HH:mm}" 
                }),
            "WorkoutSessionId", 
            "DisplayText");
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create([Bind("WorkoutSessionId,ExerciseId,Sets,Repetitions,Weight")] WorkoutSessionDetail detail)
    {
        // Ustaw UserId przed walidacją
        detail.UserId = _userManager.GetUserId(User);
        
        // Usuń błąd walidacji dla UserId, ponieważ jest ustawiane automatycznie
        ModelState.Remove(nameof(detail.UserId));
        
        if (ModelState.IsValid)
        {
            _context.Add(detail);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
        ViewData["ExerciseId"] = new SelectList(_context.Exercises, "ExerciseId", "Name", detail.ExerciseId);
        ViewData["WorkoutSessionId"] = new SelectList(
            _context.WorkoutSessions
                .Where(w => w.UserId == detail.UserId)
                .Select(w => new { 
                    w.WorkoutSessionId, 
                    DisplayText = $"{w.StartTime:dd.MM.yyyy HH:mm} - {w.EndTime:dd.MM.yyyy HH:mm}" 
                }),
            "WorkoutSessionId", 
            "DisplayText", 
            detail.WorkoutSessionId);
        return View(detail);
    }

    public async Task<IActionResult> Edit(int? id)
    {
        if (id == null) return NotFound();
        string? userId = _userManager.GetUserId(User);

        var detail = await _context.WorkoutSessionDetails.FindAsync(id);
        if (detail == null || detail.UserId != userId) return Forbid();

        ViewData["ExerciseId"] = new SelectList(_context.Exercises, "ExerciseId", "Name", detail.ExerciseId);
        ViewData["WorkoutSessionId"] = new SelectList(
            _context.WorkoutSessions
                .Where(w => w.UserId == userId)
                .Select(w => new { 
                    w.WorkoutSessionId, 
                    DisplayText = $"{w.StartTime:dd.MM.yyyy HH:mm} - {w.EndTime:dd.MM.yyyy HH:mm}" 
                }),
            "WorkoutSessionId", 
            "DisplayText", 
            detail.WorkoutSessionId);
        return View(detail);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, [Bind("WorkoutSessionDetailId,WorkoutSessionId,ExerciseId,Sets,Repetitions,Weight")] WorkoutSessionDetail detail)
    {
        if (id != detail.WorkoutSessionDetailId) return NotFound();
        string? userId = _userManager.GetUserId(User);
        if (userId == null) return Forbid();

        var orig = await _context.WorkoutSessionDetails.AsNoTracking().FirstOrDefaultAsync(w => w.WorkoutSessionDetailId == id && w.UserId == userId);
        if (orig == null) return Forbid();

        // Ustaw UserId przed walidacją
        detail.UserId = userId;
        
        // Usuń błąd walidacji dla UserId, ponieważ jest ustawiane automatycznie
        ModelState.Remove(nameof(detail.UserId));

        if (ModelState.IsValid)
        {
            try
            {
                _context.Update(detail);
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!_context.WorkoutSessionDetails.Any(w => w.WorkoutSessionDetailId == id && w.UserId == userId))
                    return NotFound();
                throw;
            }
            return RedirectToAction(nameof(Index));
        }
        ViewData["ExerciseId"] = new SelectList(_context.Exercises, "ExerciseId", "Name", detail.ExerciseId);
        ViewData["WorkoutSessionId"] = new SelectList(
            _context.WorkoutSessions
                .Where(w => w.UserId == userId)
                .Select(w => new { 
                    w.WorkoutSessionId, 
                    DisplayText = $"{w.StartTime:dd.MM.yyyy HH:mm} - {w.EndTime:dd.MM.yyyy HH:mm}" 
                }),
            "WorkoutSessionId", 
            "DisplayText", 
            detail.WorkoutSessionId);
        return View(detail);
    }

    public async Task<IActionResult> Delete(int? id)
    {
        if (id == null) return NotFound();
        string? userId = _userManager.GetUserId(User);

        var detail = await _context.WorkoutSessionDetails
            .Include(w => w.Exercise)
            .Include(w => w.WorkoutSession)
            .FirstOrDefaultAsync(w => w.WorkoutSessionDetailId == id && w.UserId == userId);
        if (detail == null) return Forbid();
        return View(detail);
    }

    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteConfirmed(int id)
    {
        string? userId = _userManager.GetUserId(User);
        var detail = await _context.WorkoutSessionDetails.FirstOrDefaultAsync(w => w.WorkoutSessionDetailId == id && w.UserId == userId);
        if (detail == null) return Forbid();
        _context.WorkoutSessionDetails.Remove(detail);
        await _context.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }
}

public class AccountController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (ModelState.IsValid && model.Email != null && model.Password != null)
        {
            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("Index", "Home");
            }
            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);
        }
        return View(model);
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (ModelState.IsValid && model.Email != null && model.Password != null)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
                return RedirectToAction("Index", "Home");
            ModelState.AddModelError("", "Invalid login attempt.");
        }
        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }
}

[Authorize]
public class StatisticsController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;

    public StatisticsController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    public async Task<IActionResult> Index()
    {
        string? userId = _userManager.GetUserId(User);
        if (userId == null) return Forbid();

        // Oblicz datę 4 tygodnie temu
        var fourWeeksAgo = DateTime.Now.AddDays(-28);

        // Pobierz wszystkie sesje treningowe użytkownika z ostatnich 4 tygodni
        var recentSessions = await _context.WorkoutSessions
            .Where(ws => ws.UserId == userId && ws.StartTime >= fourWeeksAgo)
            .Select(ws => ws.WorkoutSessionId)
            .ToListAsync();

        // Pobierz wszystkie szczegóły treningów dla tych sesji
        var workoutDetails = await _context.WorkoutSessionDetails
            .Include(wd => wd.Exercise)
            .Where(wd => wd.UserId == userId && recentSessions.Contains(wd.WorkoutSessionId))
            .ToListAsync();

        // Grupuj po ćwiczeniach i oblicz statystyki
        var statistics = workoutDetails
            .Where(wd => wd.Exercise != null)
            .GroupBy(wd => wd.Exercise)
            .Select(g => new ExerciseStatisticsViewModel
            {
                ExerciseName = g.Key?.Name ?? "Nieznane ćwiczenie",
                ExerciseId = g.Key?.ExerciseId ?? 0,
                TimesPerformed = g.Count(),
                TotalRepetitions = g.Sum(wd => wd.Sets * wd.Repetitions),
                AverageWeight = g.Average(wd => (double)wd.Weight),
                MaxWeight = g.Max(wd => (double)wd.Weight)
            })
            .OrderByDescending(s => s.TimesPerformed)
            .ToList();

        return View(statistics);
    }
}

// ViewModel dla statystyk
public class ExerciseStatisticsViewModel
{
    public string ExerciseName { get; set; } = string.Empty;
    public int ExerciseId { get; set; }
    public int TimesPerformed { get; set; }
    public int TotalRepetitions { get; set; }
    public double AverageWeight { get; set; }
    public double MaxWeight { get; set; }
}