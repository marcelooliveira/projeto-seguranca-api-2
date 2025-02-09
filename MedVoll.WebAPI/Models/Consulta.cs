using MedVoll.Web.Dtos;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MedVoll.Web.Models
{
    [Table("consultas")]
    public class Consulta
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public long Id { get; private set; }

        public string Paciente { get; private set; }

        public long MedicoId { get; private set; }

        public DateTime Data { get; private set; }

        public virtual Medico Medico { get; private set; }

        public Consulta() { }

        public Consulta(Medico medico, ConsultaDto dados)
        {
            ModificarDados(medico, dados);
        }

        public void ModificarDados(Medico medico, ConsultaDto dados)
        {
            Medico = medico;
            Paciente = dados.Paciente;
            Data = dados.Data;
        }
    }
}


