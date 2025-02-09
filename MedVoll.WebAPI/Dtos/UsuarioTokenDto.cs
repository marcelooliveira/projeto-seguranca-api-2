namespace MedVoll.Web.Dtos;

public class UsuarioTokenDto
{
    public bool Autenticado { get; set; }
    public DateTime? Expiracao { get; set; }
    public string? Token { get; set; } = string.Empty;
    public string? RefreshToken { get; set; } = string.Empty;
}
