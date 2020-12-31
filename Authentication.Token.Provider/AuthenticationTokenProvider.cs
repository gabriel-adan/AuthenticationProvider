using System;
using System.Data;
using System.Text;
using System.Security.Claims;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
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
                string query = string.Format("SELECT u.Id, u.FirstName, u.LastName, u.UserName, u.IsEnabled, u.Email FROM user u INNER JOIN user_role ur ON ur.User_Id = u.Id INNER JOIN role r ON r.Id = ur.Role_Id INNER JOIN application a ON a.Id = r.Application_Id WHERE u.IsEnabled AND u.{0} = @pUserName AND u.Password = @pPassword AND a.Name = @pAppName;", (authenticationField == EAuthenticationField.EMAIL ? "Email" : "UserName"));
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserName", "@pPassword", "@pAppName" }, new DbType[] { DbType.String, DbType.String, DbType.String }, new object[] { userName, password, authTokenConfig.AppName }))
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
                    if (!user.IsEnabled)
                        throw new ArgumentException("La cuenta existe pero no está validada o habilitada");
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

        public bool SigIn(string firstName, string lastName, string password, string userName, string email, bool isEnabled, EAuthenticationField authenticationField, IList<string> roles, string verifyCode)
        {
            transaction = null;
            try
            {
                transaction = connection.BeginTransaction();
                if (string.IsNullOrEmpty(firstName))
                    throw new ArgumentException("Se requiere un nombre");
                if (string.IsNullOrEmpty(lastName))
                    throw new ArgumentException("Se requiere un apellido");
                if (string.IsNullOrEmpty(password))
                    throw new ArgumentException("Se requiere una contraseña");
                if (authenticationField == EAuthenticationField.USERNAME && string.IsNullOrEmpty(userName))
                    throw new ArgumentException("Se requiere un nombre de usuario");
                if (authenticationField == EAuthenticationField.EMAIL && string.IsNullOrEmpty(email))
                    throw new ArgumentException("Se requiere una dirección de correo electrónico");
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
                            throw new ArgumentException("Ya existe una cuenta de usuario con estos datos");
                    }
                }
                object userId = 0;
                query = "INSERT INTO user(FirstName, LastName, UserName, Password, IsEnabled, Email, VerifyCode) VALUES (@pFirstName, @pLastName, @pUserName, @pPassword, @pIsEnabled, @pEmail, @pVerifyCode);SELECT LAST_INSERT_ID();";
                using (IDbCommand command = BuildCommand(query, 
                    new string[] { "@pFirstName", "@pLastName", "@pUserName", "@pPassword", "@pIsEnabled", "@pEmail", "@pVerifyCode" }, 
                    new DbType[] { DbType.String, DbType.String, DbType.String, DbType.String, DbType.Boolean, DbType.String, DbType.String }, 
                    new object[] { firstName, lastName, userName, password, isEnabled, email, verifyCode }))
                {
                    command.Transaction = transaction;
                    userId = command.ExecuteScalar();
                }
                if (userId != null)
                {
                    if (roles != null && roles.Count > 0)
                    {
                        IList<int> roleIds = new List<int>();
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
                            throw new Exception("Roles inválidos para el usuario. Aplicación: " + authTokenConfig.AppName);

                        query = "INSERT INTO user_role(User_Id, Role_Id) VALUES ";
                        foreach (int roleId in roleIds)
                            query += "(" + userId + ", " + roleId + "), ";
                        query += "-";
                        query = query.Replace(", -", ";");
                        
                        using (IDbCommand command = connection.CreateCommand())
                        {
                            command.CommandText = query;
                            command.Transaction = transaction;
                            command.ExecuteNonQuery();
                        }
                    }
                    else
                        throw new Exception("No se especificaron Roles para el usuario. Aplicación: " + authTokenConfig.AppName);
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

        public bool ConfirmAccount(string userName, string verifyCode, EAuthenticationField authenticationField)
        {
            try
            {
                if (string.IsNullOrEmpty(userName))
                    throw new ArgumentException("Cuenta inválida");
                string fieldName = string.Empty, fieldVerifyCode = string.Empty;
                if (authenticationField == EAuthenticationField.USERNAME)
                    fieldName = "UserName";
                if (authenticationField == EAuthenticationField.EMAIL)
                {
                    fieldName = "Email";
                    fieldVerifyCode = string.Format(" AND u.VerifyCode = '{0}'", verifyCode);
                }
                int id = 0;
                string query = string.Format("SELECT u.Id, u.IsEnabled FROM user u INNER JOIN user_role ur ON ur.User_Id = u.Id INNER JOIN role r ON r.Id = ur.Role_Id INNER JOIN application a ON a.Id = r.Application_Id WHERE u.{0} = @pUserName AND a.Name = @pAppName{1};", fieldName, fieldVerifyCode);
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserName", "@pAppName" }, new DbType[] { DbType.String, DbType.String }, new object[] { userName, authTokenConfig.AppName }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            if (reader.GetBoolean(1))
                                throw new ArgumentException("La cuenta ya se encuentra activa");
                            else
                                id = reader.GetInt32(0);
                        }
                        else
                            throw new ArgumentException("No se pudo validar la cuenta");
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

        public bool IsEnabledAccount(string userName, EAuthenticationField authenticationField)
        {
            try
            {
                bool isEnabled = false;
                string fieldName = string.Empty;
                if (authenticationField == EAuthenticationField.USERNAME)
                    fieldName = "UserName";
                if (authenticationField == EAuthenticationField.EMAIL)
                    fieldName = "Email";
                string query = string.Format("SELECT u.IsEnabled FROM user u INNER JOIN user_role ur ON ur.User_Id = u.Id INNER JOIN role r ON r.Id = ur.Role_Id INNER JOIN application a ON a.Id = r.Application_Id WHERE u.{0} = @pUserName AND a.Name = @pAppName;", fieldName);
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserName", "@pAppName" }, new DbType[] { DbType.String, DbType.String }, new object[] { userName, authTokenConfig.AppName }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                            isEnabled = reader.GetBoolean(0);
                        else
                            throw new ArgumentException("No existe la cuenta");
                    }
                }
                return isEnabled;
            }
            catch
            {
                throw;
            }
        }

        public bool ApplyUserRole(string userName, string roleName, EAuthenticationField authenticationField)
        {
            try
            {
                if (string.IsNullOrEmpty(roleName))
                    throw new ArgumentException("Rol inválido");
                string fieldName = string.Empty;
                if (authenticationField == EAuthenticationField.USERNAME)
                    fieldName = "UserName";
                if (authenticationField == EAuthenticationField.EMAIL)
                    fieldName = "Email";
                User user = null;
                string query = string.Format("SELECT u.Id, u.FirstName, u.LastName, u.UserName, u.IsEnabled, u.Email FROM user u INNER JOIN user_role ur ON ur.User_Id = u.Id INNER JOIN role r ON r.Id = ur.Role_Id INNER JOIN application a ON a.Id = r.Application_Id WHERE r.IsEnabled AND u.IsEnabled AND a.IsEnabled AND a.Name = @pAppName AND u.{0} = @pUserName;", fieldName);
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserName", "@pAppName" }, new DbType[] { DbType.String, DbType.String }, new object[] { roleName, authTokenConfig.AppName }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            user = new User();
                            user.Id = reader.GetInt32(0);
                            if (!reader.IsDBNull(1))
                                user.FirstName = reader.GetString(1);
                            if (!reader.IsDBNull(2))
                                user.LastName = reader.GetString(2);
                            if (!reader.IsDBNull(3))
                                user.UserName = reader.GetString(3);
                            user.IsEnabled = reader.GetBoolean(4);
                            if (!reader.IsDBNull(5))
                                user.Email = reader.GetString(5);
                        }
                        else
                            throw new ArgumentException("Usuario inválido");
                    }
                }
                Role role = null;
                query = string.Format("SELECT r.Id, r.Name, r.IsEnabled FROM role r INNER JOIN application a ON a.Id = r.Application_Id WHERE r.IsEnabled AND a.IsEnabled AND r.Name = @pRole AND a.Name = @pAppName;");
                using (IDbCommand command = BuildCommand(query, new string[] { "@pRole", "@pAppName" }, new DbType[] { DbType.String, DbType.String }, new object[] { roleName, authTokenConfig.AppName }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            role = new Role();
                            role.Id = reader.GetInt32(0);
                            role.Name = reader.GetString(1);
                            role.IsEnabled = reader.GetBoolean(2);
                        }
                        else
                            throw new ArgumentException("Rol no disponible");
                    }
                }
                query = "SELECT User_Id, Role_Id FROM user_role WHERE User_Id = @pUserId AND Role_Id = @pRoleId;";
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserId", "@pRoleId" }, new DbType[] { DbType.Int32, DbType.Int32 }, new object[] { user.Id, role.Id }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                            throw new ArgumentException("El usuario ya tiene asignado el Rol");
                    }
                }
                query = "INSERT INTO user_role(User_Id, Role_Id) VALUES (@pUserId, @pRoleId);";
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserId", "@pRoleId" }, new DbType[] { DbType.Int32, DbType.Int32 }, new object[] { user.Id, role.Id }))
                {
                    return command.ExecuteNonQuery() > 0;
                }
            }
            catch
            {
                throw;
            }
        }

        public bool DenyUserRole(string userName, string roleName, EAuthenticationField authenticationField)
        {
            try
            {
                if (string.IsNullOrEmpty(roleName))
                    throw new ArgumentException("Rol inválido");
                string fieldName = string.Empty;
                if (authenticationField == EAuthenticationField.USERNAME)
                    fieldName = "UserName";
                if (authenticationField == EAuthenticationField.EMAIL)
                    fieldName = "Email";
                User user = null;
                string query = string.Format("SELECT u.Id, u.FirstName, u.LastName, u.UserName, u.IsEnabled, u.Email FROM user u INNER JOIN user_role ur ON ur.User_Id = u.Id INNER JOIN role r ON r.Id = ur.Role_Id INNER JOIN application a ON a.Id = r.Application_Id WHERE r.IsEnabled AND u.IsEnabled AND a.IsEnabled AND a.Name = @pAppName AND u.{0} = @pUserName;", fieldName);
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserName", "@pAppName" }, new DbType[] { DbType.String, DbType.String }, new object[] { roleName, authTokenConfig.AppName }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            user = new User();
                            user.Id = reader.GetInt32(0);
                            if (!reader.IsDBNull(1))
                                user.FirstName = reader.GetString(1);
                            if (!reader.IsDBNull(2))
                                user.LastName = reader.GetString(2);
                            if (!reader.IsDBNull(3))
                                user.UserName = reader.GetString(3);
                            user.IsEnabled = reader.GetBoolean(4);
                            if (!reader.IsDBNull(5))
                                user.Email = reader.GetString(5);
                        }
                        else
                            throw new ArgumentException("Usuario inválido");
                    }
                }
                Role role = null;
                query = string.Format("SELECT r.Id, r.Name, r.IsEnabled FROM role r INNER JOIN application a ON a.Id = r.Application_Id WHERE r.IsEnabled AND a.IsEnabled AND r.Name = @pRole AND a.Name = @pAppName;");
                using (IDbCommand command = BuildCommand(query, new string[] { "@pRole", "@pAppName" }, new DbType[] { DbType.String, DbType.String }, new object[] { roleName, authTokenConfig.AppName }))
                {
                    using (IDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            role = new Role();
                            role.Id = reader.GetInt32(0);
                            role.Name = reader.GetString(1);
                            role.IsEnabled = reader.GetBoolean(2);
                        }
                        else
                            throw new ArgumentException("Rol no disponible");
                    }
                }
                query = "DELETE FROM user_role WHERE User_Id = @pUserId AND Role_Id = @pRoleId;";
                using (IDbCommand command = BuildCommand(query, new string[] { "@pUserId", "@pRoleId" }, new DbType[] { DbType.Int32, DbType.Int32 }, new object[] { user.Id, role.Id }))
                {
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
