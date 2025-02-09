using MedVoll.Web.Models;
using System.ComponentModel.DataAnnotations;

namespace MedVoll.Web.Dtos
{
    public class MedicoDto
    {
        public MedicoDto()
        {
        }

        public MedicoDto(Medico medico)
        {
            Id = medico.Id;
            Nome = medico.Nome;
            Email = medico.Email;
            Telefone = medico.Telefone;
            Crm = medico.Crm;
            Especialidade = medico.Especialidade;
        }

        public long? Id { get; set; }
        public string _method { get; set; }
        [Required(ErrorMessage = "Campo obrigatório"), MinLength(5, ErrorMessage = "Campo deve ter no mínimo 5 caracteres")] 
        public string Nome { get; set; }
        [Required(ErrorMessage = "Campo obrigatório"), EmailAddress] 
        public string Email { get; set; }
        [Required(ErrorMessage = "Campo obrigatório"), StringLength(6, MinimumLength = 4,
           ErrorMessage = "CRM deve ter de 4 a 6 digitos numéricos")]
        public string Crm { get; set; }
        [Required(ErrorMessage = "Campo obrigatório"), RegularExpression(@"^(?:\d{8}|\d{9}|\d{4}-\d{4}|\d{5}-\d{4}|\(\d{2}\)\s*\d{4}-\d{4}|\(\d{2}\)\s*\d{5}-\d{4}|\(\d{2}\)\s*\d{9})$",
            ErrorMessage = "Telefone inválido")]
        public string Telefone { get; set; }
        [Required(ErrorMessage = "Campo obrigatório")] 
        public Especialidade Especialidade { get; set; }
    }
}


