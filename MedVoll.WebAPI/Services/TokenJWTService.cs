using MedVoll.Web.Dtos;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace MedVoll.Web.Services;

public class TokenJWTService
{
    private readonly IConfiguration configuration;

    public TokenJWTService(IConfiguration configuration)
    {
        this.configuration = configuration;
    }

    public UsuarioTokenDto GerarTokenDeUsuario(UsuarioDto usuarioDto)
    {
        // Definimos uma lista de Claims, que são informações do usuário e que queremos que estejam no token
        var claims = new[]
        {
            new Claim("Alura","C#"),
            new Claim(JwtRegisteredClaimNames.UniqueName, usuarioDto.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // Definimos a chave de acesso ao token.O valor da chave é obtido da configuração JWTKey:key, convertida para um array de bytes via Encoding.UTF8.GetBytes.
        var chave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWTKey:key"]!));

        // Definimos as credenciais do token - chave, algoritmo de segurança e tipo de criptografia.
        var credenciais = new SigningCredentials(chave, SecurityAlgorithms.HmacSha256);

        //Definimos o tempo de expiração do token.
        //var expiracao = configuration["JWTTokenConfiguration:ExpireInMinutes"];
        //var expiracaoInMinutes = DateTime.UtcNow.AddHours(double.Parse(expiracao!));

        var expiracaoInMinutes = DateTime.UtcNow.AddMinutes(double.Parse(configuration["JWTTokenConfiguration:ExpireInMinutes"]!));

        // Definimos a descrição do token.
        JwtSecurityToken? token = null;
        try
        {
            token = new JwtSecurityToken(
             issuer: configuration["JWTTokenConfiguration:Issuer"], //Quem emitiu o token
             audience: configuration["JWTTokenConfiguration:Audience"],//Para quem é dedicado o token
             claims: claims,
             expires: expiracaoInMinutes,
             signingCredentials: credenciais
         );

        }
        catch (Exception )
        {
            throw new ArgumentException("Encontrados erro ao gerar Token!");
        }

        return new UsuarioTokenDto()
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            Expiracao = expiracaoInMinutes,
            Autenticado = true
        };
    }

    public string GerarRefreshToken()
    {
        var bytes = new byte[128];
        using var numeroRandomico = RandomNumberGenerator.Create();
        numeroRandomico.GetBytes(bytes);
        var refreshToken = Convert.ToBase64String(bytes);
        return refreshToken;
    }

    internal ClaimsPrincipal CapturaClaimsDoTokenExpirado(string token)
    {
        
        if (string.IsNullOrWhiteSpace(token))
            throw new ArgumentException("O token não pode ser nulo ou vazio.", nameof(token));
        
        var chave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWTKey:key"]!));

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = false, // Ignora a validação do tempo de expiração
            ValidateIssuerSigningKey = true,
            ValidIssuer = configuration["JWTTokenConfiguration:Issuer"],
            ValidAudience = configuration["JWTTokenConfiguration:Audience"],
            IssuerSigningKey = chave
        };

        var tokenHandlerValidator = new JwtSecurityTokenHandler();

        var principal = tokenHandlerValidator.ValidateToken(token, tokenValidationParameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
        !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("O token é inválido ou não utiliza o algoritmo esperado.");
        }        
        return principal;

    }
}
