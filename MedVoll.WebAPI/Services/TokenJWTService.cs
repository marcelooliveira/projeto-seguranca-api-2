using MedVoll.Web.Dtos;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
}
