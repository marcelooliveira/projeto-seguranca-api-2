using MedVoll.Web.Dtos;
using MedVoll.Web.Exceptions;
using MedVoll.Web.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace MedVoll.Web.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ConsultaController : ControllerBase
    {
        private readonly IConsultaService _consultaservice;
        private readonly IMedicoService _medicoService;
     

        public ConsultaController(SignInManager<IdentityUser> signInManager, IConsultaService consultaService, IMedicoService medicoService)
        {
            _consultaservice = consultaService;
            _medicoService = medicoService;            
        }

        [HttpGet("listar")]
        [Authorize(Policy = "User")]
        public async Task<IActionResult> ListarAsync([FromQuery] int page = 1)
        {
            var consultasAtivas = await _consultaservice.ListarAsync(page);        
            return Ok(consultasAtivas);
        }

        [HttpGet("formulario/{id?}")]
        public async Task<IActionResult> ObterFormularioAsync(long? id)
        {
            var dados = id.HasValue
                ? await _consultaservice.CarregarPorIdAsync(id.Value)
                : new ConsultaDto { Data = DateTime.Now };
            IEnumerable<MedicoDto> medicos = _medicoService.ListarTodos();         
            return Ok(new { medicos, dados });
        }

        [HttpPost("Salvar")]    
        public async Task<IActionResult> SalvarAsync([FromForm] ConsultaDto dados)
        {
            if (dados._method == "delete")
            {
                if (dados.Id.HasValue)
                {
                    await _consultaservice.ExcluirAsync(dados.Id.Value);
                }
                return NoContent();
            }       

            try
            {
                await _consultaservice.CadastrarAsync(dados);
                return Ok("Consulta registrada com sucesso!");
            }
            catch (RegraDeNegocioException ex)
            {
                return NotFound($"Erro:{ex.Message}");
            }
        }
    }
}
