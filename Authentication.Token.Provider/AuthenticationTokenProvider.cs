using System;
using System.Data;
using System.Text;
using System.Security.Claims;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Authentication.Token.Provider.Model;

namespace Authentication.Token.Provider
{
    public class AuthenticationTokenProvider : IAuthenticationTokenProvider
    {
        private readonly AuthTokenProviderConfiguration authTokenConfig;
        private readonly IDbConnection connection;
        private IDbTransaction transaction;

        public AuthenticationTokenProvider(IDbConnection dbConnection, AuthTokenProviderConfiguration config)
        {
            connection = dbConnection;
            authTokenConfig = config;
            connection.Open();
        }

        public string LogIn(string userName, string password, EAuthenticationField authenticationField)
        {
            string token = null;
            try
            {
                User user = null;
                IList<Claim> roles = new List<Claim>();
                string query = string.Format("SELECT u.Id, u.FirstName, u.LastName, u.UserName, u.IsEnabled, u.Email FROM User u WHERE u.{0} = @pUserName AND u.Password = @pPassword AND u.IsEnabled;", (authenticationField == EAuthenticationField.EMAIL ? "Email" : "UserName"));
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserName", "@pPassword" }, new DbType[] { DbType.String, DbType.String }, new object[] { userName, password }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            user = new User();
                            user.Id = reader.GetInt32(0);
                            user.FirstName = reader.GetString(1);
                            user.LastName = reader.GetString(2);
                            if (!reader.IsDBNull(3))
                                user.UserName = reader.GetString(3);
                            user.IsEnabled = reader.GetBoolean(4);
                            if (!reader.IsDBNull(5))
                                user.Email = reader.GetString(5);
                        }
                    }
                }
                if (user != null)
                {
                    query = "SELECT r.Name FROM User_Role ur INNER JOIN Role r ON r.Id = ur.Role_Id INNER JOIN Application a ON a.Id = r.Application_Id WHERE ur.User_Id = @pId AND a.Name = @pAppName;";
                    using (IDbCommand command = BuildCommand(query, new string[] { "@pId", "@pAppName" }, new DbType[] { DbType.Int32, DbType.String }, new object[] { user.Id, authTokenConfig.AppName }))
                    {
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
                    roles.Add(new Claim("User", user.UserName));
                    roles.Add(new Claim(ClaimTypes.Name, (authenticationField == EAuthenticationField.EMAIL ? user.Email : user.UserName)));
                    roles.Add(new Claim("UserName", user.FirstName + " " + user.LastName));
                    roles.Add(new Claim(ClaimTypes.Email, user.Email));
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

        public bool SigIn(string firstName, string lastName, string password, string userName, string email, bool isEnabled, EAuthenticationField authenticationField, IList<string> roles)
        {
            transaction = null;
            try
            {
                transaction = connection.BeginTransaction();
                if (string.IsNullOrEmpty(firstName))
                    throw new ArgumentNullException("Se requiere un nombre");
                if (string.IsNullOrEmpty(lastName))
                    throw new ArgumentNullException("Se requiere un apellido");
                if (string.IsNullOrEmpty(password))
                    throw new ArgumentNullException("Se requiere una contraseña");
                if (authenticationField == EAuthenticationField.USERNAME && string.IsNullOrEmpty(userName))
                    throw new ArgumentNullException("Se requiere un nombre de usuario");
                if (authenticationField == EAuthenticationField.EMAIL && string.IsNullOrEmpty(email))
                    throw new ArgumentNullException("Se requiere una dirección de correo electrónico");
                string fieldName = string.Empty;
                string user = string.Empty;
                if (authenticationField == EAuthenticationField.EMAIL)
                {
                    fieldName = "Email";
                    user = email;
                }
                if (authenticationField == EAuthenticationField.USERNAME)
                {
                    fieldName = "UserName";
                    user = userName;
                }
                string query = string.Format("SELECT u.Id FROM user u INNER JOIN user_role ur ON ur.User_Id = u.Id INNER JOIN role r ON r.Id = ur.Role_Id INNER JOIN application a ON a.Id = r.Application_Id WHERE u.{0} = @pUserName AND a.Name = @pAppName;", fieldName);
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserName", "@pAppName" }, new DbType[] { DbType.String, DbType.String }, new object[] { user, authTokenConfig.AppName }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                            throw new ArgumentNullException("Ya existe una cuenta de usuario con estos datos");
                    }
                }
                int userId = 0;
                query = "INSERT INTO user(FirstName, LastName, UserName, Password, IsEnabled, Email) VALUES (@pFirstName, @pLastName, @pUserName, @pPassword, @pIsEnabled, @pEmail);SELECT LAST_INSERT_ID();";
                using (IDbCommand command = BuildCommand(query, 
                    new string[] { "@pFirstName", "@pLastName", "@pUserName", "@pPassword", "@pIsEnabled", "@pEmail" }, 
                    new DbType[] { DbType.String, DbType.String, DbType.String, DbType.String, DbType.Boolean, DbType.String }, 
                    new object[] { firstName, lastName, userName, password, isEnabled, email }))
                {
                    command.Transaction = transaction;
                    userId = (int)command.ExecuteScalar();
                }
                if (userId > 0)
                {
                    IList<int> roleIds = new List<int>();
                    if (roles != null && roles.Count > 0)
                    {
                        query = "SELECT r.Id FROM role r INNER JOIN application a ON a.Id = r.Application_Id WHERE a.Name = @pAppName AND r.Name IN (";
                        foreach (string role in roles)
                            query += "'" + role + "', ";
                        query += "-";
                        query = query.Replace(", -", ");");

                        using (IDbCommand command = BuildCommand(query, new string[] { "@pAppName" }, new DbType[] { DbType.String }, new object[] { authTokenConfig.AppName }))
                        {
                            using (IDataReader reader = command.ExecuteReader())
                            {
                                while (reader.Read())
                                    roleIds.Add(reader.GetInt32(0));
                            }
                        }

                        if (roles.Count != roleIds.Count)
                            throw new Exception("Roles inválidos para la aplicación: " + authTokenConfig.AppName);

                        query = "INSERT INTO user_role(User_Id, Role_Id) VALUES (";
                        foreach (int roleId in roleIds)
                            query += userId + ", " + roleId + "), ";
                        query += "-";
                        query = query.Replace(", -", ");");

                        using (IDbCommand command = connection.CreateCommand())
                        {
                            command.CommandText = query;
                            command.Transaction = transaction;
                            command.ExecuteNonQuery();
                        }
                    }
                    transaction.Commit();
                    return true;
                }
                else
                {
                    transaction.Rollback();
                    return false;
                }
            }
            catch
            {
                if (transaction != null)
                {
                    transaction.Rollback();
                    transaction.Dispose();
                }
                throw;
            }
        }

        public bool ConfirmAccount(string userName, EAuthenticationField authenticationField)
        {
            try
            {
                if (string.IsNullOrEmpty(userName))
                    throw new ArgumentNullException("Cuenta inválida");
                string fieldName = string.Empty;
                if (authenticationField == EAuthenticationField.USERNAME)
                    fieldName = "UserName";
                if (authenticationField == EAuthenticationField.EMAIL)
                    fieldName = "Email";
                int id = 0;
                string query = string.Format("SELECT u.Id, u.IsEnabled FROM user u INNER JOIN user_role ur ON ur.User_Id = u.Id INNER JOIN role r ON r.Id = ur.Role_Id INNER JOIN application a ON a.Id = r.Application_Id WHERE u.IsEnabled AND u.{0} = @pUserName AND a.Name = @pAppName;", fieldName);
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserName", "@pAppName" }, new DbType[] { DbType.String, DbType.String }, new object[] { userName, authTokenConfig.AppName }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            if (reader.GetBoolean(1))
                                throw new ArgumentNullException("Ya existe una cuenta de usuario con estos datos");
                            else
                                id = reader.GetInt32(0);
                        }
                    }
                }
                using (IDbCommand command = connection.CreateCommand())
                {
                    command.CommandText = string.Format("UPDATE user SET IsEnabled = 1 WHERE Id = {0};", id);
                    return command.ExecuteNonQuery() > 0;
                }
            }
            catch
            {
                throw;
            }
        }

        IDbCommand BuildCommand(string query, string[] paramNames, DbType[] dbTypes, object[] values)
        {
            if (paramNames == null || dbTypes == null || values == null)
                throw new Exception("Error de parámetros al crear el comando.");
            int countParamNames = paramNames.Length;
            int countDbTypes = dbTypes.Length;
            int countValues = values.Length;
            if (countParamNames != countDbTypes || countParamNames != countValues)
                throw new Exception("Error de parámetros al crear el comando.");

            IDbCommand command = connection.CreateCommand();
            command.CommandText = query;
            for (int i = 0; i < countParamNames; i++)
            {
                string paramName = paramNames[i];
                DbType dbType = dbTypes[i];
                object value = values[i];
                IDbDataParameter parameter = command.CreateParameter();
                parameter.ParameterName = paramName;
                parameter.DbType = dbType;
                parameter.Value = value;
                command.Parameters.Add(parameter);
            }
            return command;
        }
    }
}
