namespace Authentication.Token.Provider
{
    public class AuthTokenProviderConfiguration
    {
        public string SqlAssemblyName { get; set; }
        public string SqlConnectionClassNamespace { get; set; }
        public string AuthConnectionString { get; set; }
        public string AppName { get; set; }
        public string SecretTokenKey { get; set; }
        public double TokenExpirationMinutes { get; set; }
        public string ValidIssuer { get; set; }
        public string ValidAudience { get; set; }
    }
}
