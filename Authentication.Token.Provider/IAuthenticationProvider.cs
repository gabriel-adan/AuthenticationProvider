using System;
using System.Collections.Generic;

namespace Authentication.Token.Provider
{
    public interface IAuthenticationProvider<T> : IDisposable where T : class
    {
        T LogIn(string user, string password, EAuthenticationField authenticationField);

        bool SigIn(string firstName, string lastName, string password, string userName, string email, bool isEnabled, EAuthenticationField authenticationField, IList<string> roles = null, string verifyCode = null);

        bool ConfirmAccount(string userName, string verifyCode, EAuthenticationField authenticationField);

        bool IsEnabledAccount(string userName, EAuthenticationField authenticationField);
    }
}
