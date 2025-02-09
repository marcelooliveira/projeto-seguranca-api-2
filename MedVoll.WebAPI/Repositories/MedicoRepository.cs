using MedVoll.Web.Data;
using MedVoll.Web.Interfaces;
using MedVoll.Web.Models;
using Microsoft.EntityFrameworkCore;

namespace MedVoll.Web.Repositories
{
    public class MedicoRepository : IMedicoRepository
    {
        private readonly ApplicationDbContext _context;

        public MedicoRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<bool> IsJaCadastradoAsync(string email, string crm, long? id)
        {
            return await _context.Medicos
                .AnyAsync(m => (m.Email == email || m.Crm == crm) && (!id.HasValue || m.Id != id));
        }

        public async Task<IEnumerable<Medico>> FindByEspecialidadeAsync(Especialidade especialidade)
        {
            return await _context.Medicos
                .Where(m => m.Especialidade == especialidade)
                .ToListAsync();
        }

        public async Task InsertAsync(Medico medico)
        {
            _context.Add(medico);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(Medico medico)
        {
            _context.Update(medico);
            await _context.SaveChangesAsync();
        }

        public async Task<Medico?> FindByIdAsync(long id)
        {
            return await _context.Medicos.FindAsync(id);
        }

        public async Task DeleteByIdAsync(long id)
        {
            var medico = await _context.Medicos.FindAsync(id);
            if (medico != null)
            {
                _context.Medicos.Remove(medico);
                await _context.SaveChangesAsync();
            }
        }

        public IQueryable<Medico> GetAll()
        {
            return _context.Medicos.AsQueryable();
        }
    }
}


