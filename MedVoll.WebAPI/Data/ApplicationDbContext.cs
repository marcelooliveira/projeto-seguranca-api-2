using MedVoll.Web.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MedVoll.Web.Data
{
    public class ApplicationDbContext : IdentityDbContext<VollMedUser>
    {
        public DbSet<Consulta> Consultas { get; set; }
        public DbSet<Medico> Medicos { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Medico>(entity =>
            {
                entity.HasKey(m => m.Id);
                entity.Property(m => m.Nome).HasMaxLength(100).IsRequired();
                entity.Property(m => m.Email).HasMaxLength(100).IsRequired().IsUnicode(false);
                entity.Property(m => m.Telefone).HasMaxLength(20).IsRequired();
                entity.Property(m => m.Crm).HasMaxLength(6).IsRequired().IsUnicode(false);
                entity.Property(m => m.Especialidade).HasMaxLength(100).IsRequired();
                entity.HasIndex(m => m.Email).IsUnique();
                entity.HasIndex(m => m.Crm).IsUnique();
            });

            modelBuilder.Entity<Consulta>(entity =>
            {
                entity.HasKey(c => c.Id);
                entity.Property(c => c.Paciente).HasMaxLength(100).IsRequired();
                entity.Property(c => c.Data).IsRequired();
                entity.HasOne(c => c.Medico)
                      .WithMany(m => m.Consultas)
                      .HasForeignKey(c => c.MedicoId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            base.OnModelCreating(modelBuilder);
        }
    }
}


