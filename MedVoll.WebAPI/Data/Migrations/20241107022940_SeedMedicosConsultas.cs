using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MedVoll.Web.Data.Migrations
{
    public partial class SeedMedicosConsultas : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Populando a tabela Medicos
            migrationBuilder.InsertData(
                table: "Medicos",
                columns: new[] { "Nome", "Email", "Telefone", "Crm", "Especialidade" },
                columnTypes: new[] { "string", "string", "string", "string", "int" }, 
                values: new object[,]
                {
                { "Gregory House", "house@hospital.com", "(12)12345-6781", "123456", 6 }, // Diagnóstico
                { "Meredith Grey", "meredith@hospital.com", "(12)12345-6782", "654321", 3 }, // Cirurgia Geral
                { "John Carter", "carter@hospital.com", "(12)12345-6783", "234567", 4 }, // Pediatria
                { "Derek Shepherd", "derek@hospital.com", "(12)12345-6784", "345678", 2 }, // Neurocirurgia
                { "Cristina Yang", "cristina@hospital.com", "(12)12345-6785", "456789", 1 }, // Cardiologia
                { "Alex Karev", "alex@hospital.com", "(12)12345-6786", "567890", 4 }, // Pediatria
                { "Izzie Stevens", "izzie@hospital.com", "(12)12345-6787", "678901", 5 }, // Oncologia
                { "Miranda Bailey", "miranda@hospital.com", "(12)12345-6788", "789012", 3 }, // Cirurgia Geral
                { "George O'Malley", "george@hospital.com", "(12)12345-6789", "890123", 3 }, // Cirurgia Geral
                { "Jackson Avery", "jackson@hospital.com", "(12)12345-6790", "901234", 1 }, // Cardiologia
                { "April Kepner", "april@hospital.com", "(12)12345-6791", "012345", 4 }, // Pediatria
                { "Mark Sloan", "mark@hospital.com", "(12)12345-6792", "123789", 3 }, // Cirurgia Geral
                { "Addison Montgomery", "addison@hospital.com", "(12)12345-6793", "234891", 4 }, // Pediatria
                { "Arizona Robbins", "arizona@hospital.com", "(12)12345-6794", "345912", 4 }, // Pediatria
                { "Owen Hunt", "owen@hospital.com", "(12)12345-6795", "456023", 3 }, // Cirurgia Geral
                { "James Wilson", "wilson@hospital.com", "(12)12345-6796", "567134", 5 }, // Oncologia
                { "Allison Cameron", "cameron@hospital.com", "(12)12345-6797", "678245", 6 }, // Diagnóstico
                { "Robert Chase", "chase@hospital.com", "(12)12345-6798", "789356", 6 }, // Diagnóstico
                { "Eric Foreman", "foreman@hospital.com", "(12)12345-6799", "890467", 6 }, // Diagnóstico
                { "Richard Webber", "webber@hospital.com", "(12)12345-6800", "901578", 3 }  // Cirurgia Geral

                });

            // Populando a tabela Consultas com associações fictícias com a tabela Medicos
            migrationBuilder.InsertData(
                table: "Consultas",
                columns: new[] { "MedicoId", "Paciente", "Data" },
                columnTypes: new[] { "int", "string", "DateTime" },
                values: new object[,]
                {
                { 1, "12345678901", new DateTime(2024, 11, 10, 10, 0, 0) },
                { 1, "23456789012", new DateTime(2024, 11, 11, 12, 0, 0) },
                { 2, "34567890123", new DateTime(2024, 11, 12, 9, 0, 0) },
                    // Adicione mais 17 registros fictícios
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DELETE FROM Consultas");
            migrationBuilder.Sql("DELETE FROM Medicos");
        }
    }
}
