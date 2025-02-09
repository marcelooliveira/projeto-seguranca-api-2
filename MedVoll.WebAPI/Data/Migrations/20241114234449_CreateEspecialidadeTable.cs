using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MedVoll.Web.Data.Migrations
{
    /// <inheritdoc />
    public partial class CreateEspecialidadeTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<int>(
                name: "Especialidade",
                table: "medicos",
                type: "INTEGER",
                maxLength: 100,
                nullable: false,
                oldClrType: typeof(int),
                oldType: "TEXT",
                oldMaxLength: 100);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<int>(
                name: "Especialidade",
                table: "medicos",
                type: "TEXT",
                maxLength: 100,
                nullable: false,
                oldClrType: typeof(int),
                oldType: "INTEGER",
                oldMaxLength: 100);
        }
    }
}
