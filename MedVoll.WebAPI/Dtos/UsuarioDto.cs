using System.ComponentModel.DataAnnotations;

namespace MedVoll.Web.Dtos;

public class UsuarioDto
{
    public string? Email { get; set; }
    public string? Senha { get; set; }
}
