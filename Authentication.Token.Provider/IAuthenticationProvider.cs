﻿using System;

namespace Authentication.Token.Provider
{
    public interface IAuthenticationProvider<T> : IDisposable where T : class
    {
        T LogIn(string user, string password, ELoginTypes loginType);

        bool SigIn(string firstName, string lastName, string password, string userName, string email, bool isEnabled, ELoginTypes loginType);
    }
}
