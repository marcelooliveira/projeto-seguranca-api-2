using Microsoft.OpenApi.Models;

namespace MedVoll.Web.Extensions;

public static class ConfigureSwaggerExtensions
{
    public static void ConfigureSwagger(this IServiceCollection services)
    {
        ConfigureAppServiceSwagger(services);
    }

    internal static void ConfigureAppServiceSwagger(IServiceCollection services)
    {
        services.AddSwaggerGen(
                    swagger =>
                    {
                        swagger.SwaggerDoc("v1", new OpenApiInfo { Title = "Medvoll.Web - Sua API da clínica médica.", Version = "v1" });
                        swagger.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
                        {
                            Name = "Authorization",
                            Type = SecuritySchemeType.ApiKey,
                            Scheme = "Bearer",
                            BearerFormat = "JWT",
                            In = ParameterLocation.Header,
                            Description = "Header de autorização de esquema JWT usando Bearer.",
                        });
                        swagger.AddSecurityRequirement(new OpenApiSecurityRequirement
                        {
                                {
                                    new OpenApiSecurityScheme
                                    {
                                       Reference = new OpenApiReference
                                       {
                                           Type=ReferenceType.SecurityScheme,
                                           Id="Bearer"

                                       }
                                    },
                                    new string[]{}
                                }
                        });
                    });
    }
}