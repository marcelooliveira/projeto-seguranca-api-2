using MedVoll.Web.Dtos;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace MedVoll.Web.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController:ControllerBase
{
    private readonly UserManager<IdentityUser> userManager;
    private readonly SignInManager<IdentityUser> signInManager;
    public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
    {
        this.userManager = userManager;
        this.signInManager = signInManager;
    }

    //Endpoints
    [HttpPost("registrar-usuario")]
    public async Task<IActionResult> RegistrarUsuarioAsync([FromBody] UsuarioDto usuarioDto)
    {
        var usuarioReg = await userManager.FindByEmailAsync(usuarioDto.Email!);
        if (usuarioReg is not null)
        {
            return BadRequest("Usuário já foi registrado na base de dados.");
        }

        var usuario = new IdentityUser
        {
            UserName = usuarioDto.Email,
            Email = usuarioDto.Email, 
            EmailConfirmed = true 
        };
        var result = await userManager.CreateAsync(usuario, usuarioDto.Senha);
        if (!result.Succeeded)
        {
            return BadRequest($"Falha ao registrar usuário : {result.Errors}");
        }
        await signInManager.SignInAsync(usuario, isPersistent: false);

        return Ok("Usuário Criado com sucesso!");
    }

    [HttpPost("login")]
    public async Task<IActionResult> LoginAsync([FromBody] UsuarioDto usuarioDto)
    {
        var result = await signInManager.PasswordSignInAsync(usuarioDto.Email!, usuarioDto.Senha!, isPersistent: false, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            return BadRequest("Falha no login do usuário.");
        }
        return Ok("Logado com sucesso!");
    }

    [HttpPost("refresh-token/revoke/{email}")]
    public async Task<IActionResult> RevokeTokenAsync(string email)
    {
        // Localiza o usuário pelo email
        var usuario = await userManager.FindByEmailAsync(email);
        if (usuario is null)
        {
            return BadRequest("Usuário não encontrado.");
        }

        // Atualiza o usuário na base de dados
        await userManager.UpdateAsync(usuario);

        return NoContent(); // Retorna 204 indicando que a operação foi bem-sucedida sem resposta adicional
    }
}
