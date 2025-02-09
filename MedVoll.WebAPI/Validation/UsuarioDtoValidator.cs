using FluentValidation;
using MedVoll.Web.Dtos;

namespace MedVoll.Web.Validation;

public class UsuarioDtoValidator : AbstractValidator<UsuarioDto>
{
    public UsuarioDtoValidator()
    {
        RuleFor(u => u.Email)
            .NotEmpty().WithMessage("O campo Email é obrigatório.")
            .Matches(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .WithMessage("O e-mail inserido não é válido.");

        RuleFor(u => u.Senha)
            .NotEmpty().WithMessage("O campo Senha é obrigatório.")
            .Matches(@"^(?=.*[0-9])(?=.*[!@#$%^&*(),.?\:{}|<>]).{6,}$")
            .WithMessage("A senha deve conter ao menos 6 caracteres, incluindo um número e um caractere especial.");
    }
}