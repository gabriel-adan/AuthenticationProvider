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
                        using (IDataReader reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                string role = reader.GetString(0);
                                roles.Add(new Claim(ClaimTypes.Role, role));
                            }
                        }
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

        public bool SigIn(string firstName, string lastName, string password, string userName, string email, bool isEnabled, ELoginTypes loginType)
        {
            try
            {
                if (loginType == ELoginTypes.USERNAME && string.IsNullOrEmpty(userName))
                    throw new ArgumentNullException("Se requiere un nombre de usuario");
                if (loginType == ELoginTypes.EMAIL && string.IsNullOrEmpty(email))
                    throw new ArgumentNullException("Se requiere una dirección de correo electrónico");
                string fieldName = string.Empty;
                string user = string.Empty;
                if (loginType == ELoginTypes.EMAIL)
                {
                    fieldName = "Email";
                    user = email;
                }
                if (loginType == ELoginTypes.USERNAME)
                {
                    fieldName = "UserName";
                    user = userName;
                }
                using (IDbCommand command = connection.CreateCommand())
                {
                    command.CommandText = string.Format("SELECT u.Id, u.FirstName, u.LastName, u.UserName, u.IsEnabled, u.Email FROM user u INNER JOIN user_role ur ON ur.User_Id = u.Id INNER JOIN role r ON r.Id = ur.Role_Id INNER JOIN application a ON a.Id = r.Application_Id WHERE u.{0} = @pUserName AND a.Name = @pAppName;", fieldName);
                    IDbDataParameter userNameParameter = command.CreateParameter();
                    userNameParameter.DbType = DbType.String;
                    userNameParameter.ParameterName = "@pUserName";
                    userNameParameter.Value = user;
                    command.Parameters.Add(userNameParameter);
                    IDbDataParameter appNameParameter = command.CreateParameter();
                    appNameParameter.DbType = DbType.String;
                    appNameParameter.ParameterName = "@pAppName";
                    appNameParameter.Value = authTokenConfig.AppName;
                    command.Parameters.Add(appNameParameter);
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                            throw new ArgumentNullException("Ya existe una cuenta de usuario con estos datos");
                    }
                }
                using (IDbCommand command = connection.CreateCommand())
                {
                    command.CommandText = "INSERT INTO user(FirstName, LastName, UserName, Password, IsEnabled, Email) VALUES (@pFirstName, @pLastName, @pUserName, @pPassword, @pIsEnabled, @pEmail);";
                    IDbDataParameter firstNameParameter = command.CreateParameter();
                    firstNameParameter.DbType = DbType.String;
                    firstNameParameter.ParameterName = "@pFirstName";
                    firstNameParameter.Value = firstName;
                    command.Parameters.Add(firstNameParameter);
                    IDbDataParameter lastNameParameter = command.CreateParameter();
                    lastNameParameter.DbType = DbType.String;
                    lastNameParameter.ParameterName = "@pLastName";
                    lastNameParameter.Value = lastName;
                    command.Parameters.Add(lastNameParameter);
                    IDbDataParameter userNameParameter = command.CreateParameter();
                    userNameParameter.DbType = DbType.String;
                    userNameParameter.ParameterName = "@pUserName";
                    userNameParameter.Value = userName;
                    command.Parameters.Add(userNameParameter);
                    IDbDataParameter passwordParameter = command.CreateParameter();
                    passwordParameter.DbType = DbType.String;
                    passwordParameter.ParameterName = "@pPassword";
                    passwordParameter.Value = password;
                    command.Parameters.Add(passwordParameter);
                    IDbDataParameter isEnabledParameter = command.CreateParameter();
                    isEnabledParameter.DbType = DbType.Boolean;
                    isEnabledParameter.ParameterName = "@pIsEnabled";
                    isEnabledParameter.Value = isEnabled;
                    command.Parameters.Add(isEnabledParameter);
                    IDbDataParameter emailParameter = command.CreateParameter();
                    emailParameter.DbType = DbType.String;
                    emailParameter.ParameterName = "@pEmail";
                    emailParameter.Value = email;
                    command.Parameters.Add(emailParameter);
                    return command.ExecuteNonQuery() > 0;
                }
            }
            catch
            {
                throw;
            }
        }
    }
}
