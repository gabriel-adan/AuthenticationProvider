using System;
using System.Data;
using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Token.Provider
{
    public static class AuthenticationTokenExtentions
    {
        public static IServiceCollection AddAutenticationToken(this IServiceCollection services, IConfiguration configuration)
        {
            AuthTokenProviderConfiguration authProviderConfiguration = new AuthTokenProviderConfiguration();
            configuration.Bind("AuthTokenProviderConfiguration", authProviderConfiguration);
            Assembly sqlAssembly = Assembly.LoadFrom(authProviderConfiguration.SqlAssemblyName);
            Type sqlType = sqlAssembly.GetType(authProviderConfiguration.SqlConnectionClassNamespace);
            IDbConnection sqlConnection = (IDbConnection)Activator.CreateInstance(sqlType);
            sqlConnection.ConnectionString = authProviderConfiguration.AuthConnectionString;
            object authInstance = Activator.CreateInstance(typeof(AuthenticationTokenProvider), sqlConnection, authProviderConfiguration);
            services.AddSingleton(typeof(IAuthenticationTokenProvider), authInstance);
            byte[] secretKey = Encoding.ASCII.GetBytes(authProviderConfiguration.SecretTokenKey);
            services.AddAuthentication(auth =>
            {
                auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(token =>
            {
                token.RequireHttpsMetadata = true;
                token.SaveToken = true;
                token.TokenValidationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = new SymmetricSecurityKey(secretKey),
                    ValidIssuer = authProviderConfiguration.ValidIssuer,
                    ValidAudience = authProviderConfiguration.ValidAudience,
                    ValidateIssuerSigningKey = true,
                    RequireExpirationTime = true,
                    ValidateLifetime = true,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ClockSkew = TimeSpan.Zero
                };
            });

            return services;
        }
    }
}
