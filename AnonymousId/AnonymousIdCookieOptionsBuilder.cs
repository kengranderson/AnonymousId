using System;

namespace ReturnTrue.AspNetCore.Identity.Anonymous
{
    public class AnonymousIdCookieOptionsBuilder
    {
        const string DEFAULT_COOKIE_NAME = ".ASPXANONYMOUS";
        const string DEFAULT_COOKIE_PATH = "/";
        const int DEFAULT_COOKIE_TIMEOUT = 100000;
        const int MINIMUM_COOKIE_TIMEOUT = 1;
        const int MAXIMUM_COOKIE_TIMEOUT = 60 * 60 * 24 * 365 * 2;
        const bool DEFAULT_COOKIE_REQUIRE_SSL = false;
        
        string _cookieName;
        string _cookiePath;
        int? _cookieTimeout;
        string _cookieDomain;
        bool? _cookieRequireSsl;

        public AnonymousIdCookieOptionsBuilder SetCustomCookieName(string cookieName)
        {
            _cookieName = cookieName;
            return this;
        }

        public AnonymousIdCookieOptionsBuilder SetCustomCookiePath(string cookiePath)
        {
            _cookiePath = cookiePath;
            return this;
        }

        public AnonymousIdCookieOptionsBuilder SetCustomCookieTimeout(int cookieTimeout)
        {
            _cookieTimeout = Math.Min(Math.Max(MINIMUM_COOKIE_TIMEOUT, cookieTimeout), MAXIMUM_COOKIE_TIMEOUT);
            return this;
        }

        public AnonymousIdCookieOptionsBuilder SetCustomCookieDomain(string cookieDomain)
        {
            _cookieDomain = cookieDomain;
            return this;
        }

        public AnonymousIdCookieOptionsBuilder SetCustomCookieRequireSsl(bool cookieRequireSsl)
        {
            _cookieRequireSsl = cookieRequireSsl;
            return this;
        }

        public AnonymousIdCookieOptions Build()
        {
            AnonymousIdCookieOptions options = new()
            {
                Name = _cookieName ?? DEFAULT_COOKIE_NAME,
                Path = _cookiePath ?? DEFAULT_COOKIE_PATH,
                Timeout = _cookieTimeout ?? DEFAULT_COOKIE_TIMEOUT,
                Secure = _cookieRequireSsl ?? DEFAULT_COOKIE_REQUIRE_SSL
            };

            if (!string.IsNullOrWhiteSpace(_cookieDomain))
            {
                options.Domain = _cookieDomain;
            }

            return options;
        }
    }
}