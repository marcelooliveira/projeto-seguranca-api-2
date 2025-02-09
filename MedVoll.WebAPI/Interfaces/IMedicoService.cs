using MedVoll.Web.Dtos;
using MedVoll.Web.Models;

namespace MedVoll.Web.Interfaces
{
    public interface IMedicoService
    {
        Task CadastrarAsync(MedicoDto dados);
        Task<MedicoDto> CarregarPorIdAsync(long id);
        Task ExcluirAsync(long id);
        Task<PaginatedList<MedicoDto>> ListarAsync(int? page);
        IEnumerable<MedicoDto> ListarTodos();
        Task<IEnumerable<MedicoDto>> ListarPorEspecialidadeAsync(Especialidade especialidade);

    }
}