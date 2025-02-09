using MedVoll.Web.Dtos;
using MedVoll.Web.Models;
using MedVoll.Web.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace MedVoll.Web.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController:ControllerBase
{
    private readonly UserManager<IdentityUser> userManager;
    private readonly SignInManager<IdentityUser> signInManager;
    private readonly TokenJWTService tokenJWTService;
    private readonly IConfiguration configuration;
    public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, TokenJWTService tokenJWTService, IConfiguration configuration)
    {
        this.userManager = userManager;
        this.signInManager = signInManager;
        this.tokenJWTService = tokenJWTService;
        this.configuration = configuration;
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

        return Ok(new {Mensagem="Usuario registrado com sucesso!",Token= tokenJWTService.GerarTokenDeUsuario(usuarioDto)});
    }

    [HttpPost("login")]
    public async Task<IActionResult> LoginAsync([FromBody] UsuarioDto usuarioDto)
    {
        var usuario = await userManager.FindByEmailAsync(usuarioDto.Email!);
        if (usuario is null)
        {
            return BadRequest("usuário não encontrado.");
        }
            
        var refreshToken = tokenJWTService.GerarRefreshToken();

        var result = await signInManager.PasswordSignInAsync(usuarioDto.Email!, usuarioDto.Senha!, isPersistent: false, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            return BadRequest("Falha no login do usuário.");
        }
        var userTokenDto = tokenJWTService.GerarTokenDeUsuario(usuarioDto);
        userTokenDto.RefreshToken = refreshToken;

        return Ok(new { Mensagem = "Login realizado com sucesso!", Token = userTokenDto });
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
