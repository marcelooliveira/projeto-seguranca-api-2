using MedVoll.Web.Dtos;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MedVoll.Web.Models
{
    [Table("medicos")]
    public class Medico
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public long Id { get; private set; }

        public string Nome { get; private set; }

        public string Email { get; private set; }

        public string Telefone { get; private set; }

        public string Crm { get; private set; }

        public Especialidade Especialidade { get; private set; }

        public virtual ICollection<Consulta>? Consultas { get; set; }
        public Medico() { }
        public Medico(MedicoDto dados)
        {
            AtualizarDados(dados);
        }

        public void AtualizarDados(MedicoDto dados)
        {
            Nome = dados.Nome;
            Email = dados.Email;
            Telefone = dados.Telefone;
            Crm = dados.Crm;
            Especialidade = dados.Especialidade;
        }
    }
}


