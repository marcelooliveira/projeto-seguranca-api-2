using Microsoft.AspNetCore.Mvc;

namespace MedVoll.Web.Controllers
{
    public class ErroController : Controller
    {
        [Route("Erro/404")]
        public IActionResult NotFoundPage()
        {
            return View("404");
        }

        [Route("Erro/500")]
        public IActionResult InternalServerError()
        {
            return View("500");
        }
    }
}