using System;
using System.Data;
using System.Text;
using System.Security.Claims;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Authentication.Token.Provider
{
    public class AuthenticationTokenProvider : IAuthenticationTokenProvider
    {
        private readonly IDbConnection connection;
        private readonly AuthTokenProviderConfiguration authTokenConfig;

        public AuthenticationTokenProvider(IDbConnection dbConnection, AuthTokenProviderConfiguration config)
        {
            connection = dbConnection;
            authTokenConfig = config;
            connection.Open();
        }

        public string LogIn(string user, string password, ELoginTypes loginType)
        {
            string token = null;
            try
            {
                int id = 0;
                string fullName = string.Empty, userName = string.Empty, email = string.Empty;
                IList<Claim> roles = new List<Claim>();
                using (IDbCommand command = connection.CreateCommand())
                {
                    command.CommandText = string.Format("SELECT u.Id, CONCAT(u.FirstName, ' ', u.LastName) AS FullName, u.UserName, u.Email FROM User u WHERE u.{0} = @pUserName AND u.Password = @pPassword AND u.IsEnabled;", (loginType == ELoginTypes.EMAIL ? "Email" : "UserName"));
                    IDbDataParameter userNameParameter = command.CreateParameter();
                    userNameParameter.DbType = DbType.String;
                    userNameParameter.ParameterName = "@pUserName";
                    userNameParameter.Value = user;
                    command.Parameters.Add(userNameParameter);
                    IDbDataParameter passwordParameter = command.CreateParameter();
                    passwordParameter.DbType = DbType.String;
                    passwordParameter.ParameterName = "@pPassword";
                    passwordParameter.Value = password;
                    command.Parameters.Add(passwordParameter);
                    IDataReader reader = command.ExecuteReader();
                    if (reader.Read())
                    {
                        id = reader.GetInt32(0);
                        fullName = reader.GetString(1);
                        if (!reader.IsDBNull(2))
                            userName = reader.GetString(2);
                        if (!reader.IsDBNull(3))
                            email = reader.GetString(3);
                    }
                    command.Dispose();
                    reader.Close();
                    reader.Dispose();
                }
                if (id > 0)
                {
                    using (IDbCommand command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT r.Name FROM User_Role ur INNER JOIN Role r ON r.Id = ur.Role_Id INNER JOIN Application a ON a.Id = r.Application_Id WHERE ur.User_Id = @pId AND a.Name = @pAppName;";
                        IDbDataParameter userIdParameter = command.CreateParameter();
                        userIdParameter.DbType = DbType.Int32;
                        userIdParameter.ParameterName = "@pId";
                        userIdParameter.Value = id;
                        command.Parameters.Add(userIdParameter);
                        IDbDataParameter appNameParameter = command.CreateParameter();
                        appNameParameter.DbType = DbType.String;
                        appNameParameter.ParameterName = "@pAppName";
                        appNameParameter.Value = authTokenConfig.AppName;
                        command.Parameters.Add(appNameParameter);
                        IDataReader reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            string role = reader.GetString(0);
                            roles.Add(new Claim(ClaimTypes.Role, role));
                        }
                        command.Dispose();
                        reader.Close();
                        reader.Dispose();
                    }

                    string secretTokenKey = authTokenConfig.SecretTokenKey;
                    byte[] secretKey = Encoding.ASCII.GetBytes(secretTokenKey);
                    string validIssuer = authTokenConfig.ValidIssuer;
                    string validAudience = authTokenConfig.ValidAudience;
                    double tokenExpirationMinutes = authTokenConfig.TokenExpirationMinutes;
                    roles.Add(new Claim("User", userName));
                    roles.Add(new Claim(ClaimTypes.Name, (loginType == ELoginTypes.EMAIL ? email : userName)));
                    roles.Add(new Claim("UserName", fullName));
                    roles.Add(new Claim(ClaimTypes.Email, email));
                    roles.Add(new Claim(ClaimTypes.System, authTokenConfig.AppName));
                    roles.Add(new Claim(JwtHeaderParameterNames.Kid, Guid.NewGuid().ToString()));
                    var jwToken = new JwtSecurityToken(
                        issuer: validIssuer,
                        audience: validAudience,
                        claims: roles,
                        notBefore: new DateTimeOffset(DateTime.Now).DateTime,
                        expires: new DateTimeOffset(DateTime.Now.AddMinutes(tokenExpirationMinutes)).DateTime,
                        signingCredentials: new SigningCredentials(new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256Signature)
                    );
                    token = new JwtSecurityTokenHandler().WriteToken(jwToken);
                }
                return token;
            }
            catch
            {
                throw;
            }
        }

        public void Dispose()
        {
            connection.Close();
            connection.Dispose();
        }
    }
}
