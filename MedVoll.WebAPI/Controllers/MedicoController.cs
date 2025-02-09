using MedVoll.Web.Dtos;
using MedVoll.Web.Exceptions;
using MedVoll.Web.Interfaces;
using MedVoll.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MedVoll.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class MedicoController : ControllerBase
    {
        private const string PaginaCadastro = "Formulario";
        private readonly IMedicoService _service;
        public MedicoController(IMedicoService service)            
        {
            _service = service;
        }

        [HttpGet("Listar")]    
        public async Task<IActionResult> ListarAsync([FromQuery] int page = 1)
        {
            var medicosCadastrados = await _service.ListarAsync(page);
     
            return Ok(medicosCadastrados);
        }

        [HttpGet("formulario/{id?}")]   
        public async Task<IActionResult> ObterFormularioAsync(long? id)
        {
            var dados = id.HasValue
                ? await _service.CarregarPorIdAsync(id.Value)
                : new MedicoDto();

            return Ok(new { PaginaCadastro, dados });
        }

        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken()]
        [HttpPost]
        public async Task<IActionResult> SalvarAsync([FromForm] MedicoDto dados)
        {
            if (dados._method == "delete")
            {
                await _service.ExcluirAsync(dados.Id.Value);
                return NoContent();
            }
            try
            {
                await _service.CadastrarAsync(dados);
                return Ok("Dados salvos com sucesso!");
            }
            catch (RegraDeNegocioException ex)
            {
               
                return NotFound(new{dados,ex.Message});
            }
        }

        [HttpGet("especialidade/{especialidade}")]       
        public async Task<IActionResult> ListarPorEspecialidadeAsync(string especialidade)
        {
            if (Enum.TryParse(especialidade, out Especialidade especEnum))
            {
                var medicos = await _service.ListarPorEspecialidadeAsync(especEnum);
                return Ok(medicos);
            }
            return BadRequest("Especialidade inválida.");
        }
    }
}
