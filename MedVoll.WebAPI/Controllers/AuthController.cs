using FluentValidation;
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
    private readonly UserManager<VollMedUser> userManager;
    private readonly SignInManager<VollMedUser> signInManager;
    private readonly IValidator<UsuarioDto> validator;
    private readonly TokenJWTService tokenJWTService;
    private readonly IConfiguration configuration;
    public AuthController(UserManager<VollMedUser> userManager, SignInManager<VollMedUser> signInManager, IValidator<UsuarioDto> validator, TokenJWTService tokenJWTService, IConfiguration configuration)
    {
        this.userManager = userManager;
        this.signInManager = signInManager;
        this.validator = validator;
        this.tokenJWTService = tokenJWTService;
        this.configuration = configuration;
    }

    //Endpoints
    [HttpPost("registrar-usuario")]
    public async Task<IActionResult> RegistrarUsuarioAsync([FromBody] UsuarioDto usuarioDto)
    {
        var validationResult = await validator.ValidateAsync(usuarioDto);       
        if (!validationResult.IsValid)
        {
            return BadRequest(validationResult.Errors.GroupBy(x => x.PropertyName)
              .ToDictionary(
                g => g.Key,
                g => g.Select(x => x.ErrorMessage).ToArray()
              ));
        }

        var usuarioReg = await userManager.FindByEmailAsync(usuarioDto.Email!);
        if (usuarioReg is not null)
        {
            return BadRequest("Usuário já foi registrado na base de dados.");
        }

        var usuario = new VollMedUser
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
        var validationResult = await validator.ValidateAsync(usuarioDto);
        if (!validationResult.IsValid)
        {
            return BadRequest(validationResult.Errors.GroupBy(x => x.PropertyName)
              .ToDictionary(
                g => g.Key,
                g => g.Select(x => x.ErrorMessage).ToArray()
              ));
        }
        var usuario = await userManager.FindByEmailAsync(usuarioDto.Email!);
        if (usuario is null)
        {
            return BadRequest("usuário não encontrado.");
        }
            
        var refreshToken = tokenJWTService.GerarRefreshToken();

        //Adicionar o refresh token ao usuário
        var expire = int.TryParse(configuration["JWTTokenConfiguration:RefreshExpireInMinutes"],
                           out int refreshExpireInMinutes);
        usuario.ExpireTime =
                        DateTime.Now.AddMinutes(refreshExpireInMinutes);
        usuario.RefreshToken = refreshToken;
        await userManager.UpdateAsync(usuario);

        //Verifica se o refresh token é válido
        if (usuario == null || !usuario.RefreshToken!.Equals(refreshToken) || usuario.ExpireTime <= DateTime.Now)
        {
            return BadRequest("Refresh token expirado.");
        }

        var result = await signInManager.PasswordSignInAsync(usuarioDto.Email!, usuarioDto.Senha!, isPersistent: false, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            return BadRequest("Falha no login do usuário.");
        }
        var userTokenDto = tokenJWTService.GerarTokenDeUsuario(usuarioDto);
        userTokenDto.RefreshToken = refreshToken;

        return Ok(new { Mensagem = "Login realizado com sucesso!", Token = userTokenDto });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RecuperaRefreshToken(UsuarioTokenDto userToken)
    {   
        string? token = userToken.Token ?? throw new ArgumentException(nameof(userToken));

        string? refreshToken = userToken.RefreshToken ?? throw new ArgumentException(nameof(userToken));

        var principal = tokenJWTService.CapturaClaimsDoTokenExpirado(token);

        if (principal == null)
        {
            return BadRequest("Token inválido/Refresh token.");
        }

        //Cria um novo usuário com as informações do principal
        var novoUsuarioDTO = new UsuarioDto
        {
            Email = principal.Identity?.Name,
            Senha = principal.Claims.FirstOrDefault(c => c.Type == "password")?.Value,            
        };
         
        var vollMedUser = await userManager.FindByEmailAsync(novoUsuarioDTO.Email!);

        //Verifica se o refresh token é válido
        if (vollMedUser == null || !vollMedUser.RefreshToken!.Equals(refreshToken) || vollMedUser.ExpireTime <= DateTime.Now)
        {
            return BadRequest("Refresh token inválido.");
        }

        //Gera um novo token e um novo refresh token
        var novoToken = tokenJWTService.GerarTokenDeUsuario(novoUsuarioDTO);
        var novoRefreshToken = tokenJWTService.GerarRefreshToken();

        //Atualiza o refresh token do usuário
        vollMedUser.RefreshToken = novoRefreshToken;
        vollMedUser.ExpireTime = DateTime.Now.AddMinutes(double.Parse(configuration["JWTTokenConfiguration:RefreshExpireInMinutes"]!));

        //Atualiza o usuário
        await userManager.UpdateAsync(vollMedUser);

        //Retorna o novo token e o novo refresh token
        return Ok(new { novoToken.Token, novoRefreshToken });
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

        // Remove o refresh token do usuário
        usuario.RefreshToken = null;        

        // Atualiza o usuário na base de dados
        await userManager.UpdateAsync(usuario);

        return NoContent(); // Retorna 204 indicando que a operação foi bem-sucedida sem resposta adicional
    }
}
