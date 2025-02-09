using MedVoll.Web.Data;
using MedVoll.Web.Interfaces;
using MedVoll.Web.Repositories;
using MedVoll.Web.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using MedVoll.Web.Extensions;
using FluentValidation;
using MedVoll.Web.Validation;
using MedVoll.Web.Dtos;
using MedVoll.Web.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

var connectionString = builder.Configuration.GetConnectionString("SqliteConnection");
builder.Services.AddDbContext<ApplicationDbContext>(x => x.UseSqlite(connectionString));

builder.Services.AddDefaultIdentity<VollMedUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

////////////////////// Swagger //////////////////////
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

////////////////////// Repositories e Services //////////////////////
builder.Services.AddTransient<IMedicoRepository, MedicoRepository>();
builder.Services.AddTransient<IConsultaRepository, ConsultaRepository>();
builder.Services.AddTransient<IMedicoService, MedicoService>();
builder.Services.AddTransient<IConsultaService, ConsultaService>();

//validadores
builder.Services.AddScoped<IValidator<UsuarioDto>, UsuarioDtoValidator>();

//tokenjwtservice
builder.Services.AddScoped<TokenJWTService>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(
    opt => opt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidAudience = builder.Configuration["JWTTokenConfiguration:Audience"],
        ValidIssuer = builder.Configuration["JWTTokenConfiguration:Issuer"],
        IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["JWTKey:key"]!)),
    });

builder.Services.ConfigureSwagger();

builder.Services.AddAuthorization(auth => {
    auth.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
    auth.AddPolicy("User", policy => policy.RequireRole("User"));
});

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("Todas", policy =>
    {
        policy.AllowAnyOrigin() // Permite todas as origens
              .AllowAnyMethod() // Permite todos os métodos HTTP
              .AllowAnyHeader(); // Permite todos os cabeçalhos       
     });

    // Política restrita para o ambiente de produção
    options.AddPolicy("OrigensEspecificas", policy =>
    {
        policy.WithOrigins("https://www.exemplo.com", "https://app.exemplo.com")
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseHttpsRedirection();
    app.UseCors("Todas");
}
else
{
    app.UseHsts();
    app.UseHttpsRedirection();
    app.UseCors("OrigensEspecificas");
}

app.UseAuthentication();

app.UseAuthorization();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        await IdentitySeeder.SeedUsersAsync(services);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Erro ao executar o Seeder: {ex.Message}");
    }
}

app.MapControllers();
app.Run();
