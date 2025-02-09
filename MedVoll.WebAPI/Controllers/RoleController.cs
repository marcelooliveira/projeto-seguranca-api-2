using MedVoll.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace MedVoll.Web.Controllers;

[Route("api/[controller]")]
[ApiController]
public class RoleController:ControllerBase
{
    private readonly RoleManager<IdentityRole> roleManager;
    private readonly UserManager<VollMedUser> userManager;
    public RoleController(RoleManager<IdentityRole> roleManager, UserManager<VollMedUser> userManager)
    {
        this.roleManager = roleManager;
        this.userManager = userManager;
    }

    [HttpPost("registrar-papel")]
    public async Task<IActionResult> RegistrarRoleAsync(string papel)
    {
        var newRole = await roleManager.FindByNameAsync(papel);
        if (newRole is not null)
        {
            return BadRequest("Papel/Cargo já foi registrada na base de dados.");
        }
        var result = await roleManager.CreateAsync(new IdentityRole(papel));
        if (!result.Succeeded)
        {
            return BadRequest($"Falha ao registrar Papel/Cargo.");
        }
        return Ok(new { Mensagem = "Papel/Cargo registrada com sucesso." });
    }

    [HttpPost("atribuir-papel")]
    public async Task<IActionResult> AtribuirRoleAsync(string email, string papel)
    {
        var user = await userManager.FindByEmailAsync(email);
        if (user is null)
        {
            return BadRequest("Usuário não encontrado.");
        }
        var role = await roleManager.FindByNameAsync(papel);
        if (role is null)
        {
            return BadRequest("Papel/Cargo não encontrado.");
        }
        var result = await userManager.AddToRoleAsync(user, role.Name!);
        if (!result.Succeeded)
        {        
            return BadRequest($"Falha ao atribuir Papel/Cargo.");
        }
        return Ok(new { Mensagem = "Papel/Cargo atribuído com sucesso." });
    }
}
