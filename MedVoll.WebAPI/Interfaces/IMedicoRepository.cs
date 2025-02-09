using MedVoll.Web.Models;

namespace MedVoll.Web.Interfaces
{
    public interface IMedicoRepository
    {
        Task<bool> IsJaCadastradoAsync(string email, string crm, long? id);
        Task<IEnumerable<Medico>> FindByEspecialidadeAsync(Especialidade especialidade);
        Task InsertAsync(Medico medico);
        Task UpdateAsync(Medico medico);
        Task<Medico?> FindByIdAsync(long id);
        Task DeleteByIdAsync(long id);
        IQueryable<Medico> GetAll();
    }
}


