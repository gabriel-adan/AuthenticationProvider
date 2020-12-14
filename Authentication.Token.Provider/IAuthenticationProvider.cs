using System;

namespace Authentication.Token.Provider
{
    public interface IAuthenticationProvider<T> : IDisposable where T : class
    {
        T LogIn(string user, string password);
    }
}
