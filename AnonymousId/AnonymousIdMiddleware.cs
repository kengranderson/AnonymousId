using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace ReturnTrue.AspNetCore.Identity.Anonymous
{
    public class AnonymousIdMiddleware
    {
        readonly RequestDelegate _nextDelegate;
        readonly AnonymousIdCookieOptions _cookieOptions;

        public AnonymousIdMiddleware(RequestDelegate nextDelegate, AnonymousIdCookieOptions cookieOptions)
        {
            _nextDelegate = nextDelegate;
            _cookieOptions = cookieOptions;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            HandleRequest(httpContext);
            await _nextDelegate.Invoke(httpContext);
        }

        public void HandleRequest(HttpContext httpContext)
        {
            string encodedValue;
            var isAuthenticated = httpContext.User.Identity.IsAuthenticated;
            DateTime now = DateTime.Now;

            // Handle secure cookies over an unsecured connection
            if (_cookieOptions.Secure && !httpContext.Request.IsHttps)
            {
                encodedValue = httpContext.Request.Cookies[_cookieOptions.Name];
                if (!string.IsNullOrWhiteSpace(encodedValue))
                {
                    httpContext.Response.Cookies.Delete(_cookieOptions.Name);
                }

                // Adds the feature to request collection
                httpContext.Features.Set<IAnonymousIdFeature>(new AnonymousIdFeature());

                return;
            }

            // Gets the value and anonymous Id data from the cookie, if available
            encodedValue = httpContext.Request.Cookies[_cookieOptions.Name];
            var decodedValue = AnonymousIdEncoder.Decode(encodedValue);

            string anonymousId = null;

            if (decodedValue != null && !string.IsNullOrWhiteSpace(decodedValue.AnonymousId))
            {
                // Copy the existing value in Request header
                anonymousId = decodedValue.AnonymousId;

                // Adds the feature to request collection
                httpContext.Features.Set<IAnonymousIdFeature>(new AnonymousIdFeature()
                {
                    AnonymousId = anonymousId
                });
            }

            // User is already authenticated
            if (isAuthenticated)
            {
                return;
            }

            // Don't create a secure cookie in an unsecured connection
            if (_cookieOptions.Secure && !httpContext.Request.IsHttps)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(anonymousId))
            {
                // Creates a new identity
                anonymousId = Guid.NewGuid().ToString();

                // Adds the feature to request collection
                httpContext.Features.Set<IAnonymousIdFeature>(new AnonymousIdFeature()
                {
                    AnonymousId = anonymousId
                });
            }
            else
            {
                // Sliding expiration is not required for this request
                if (!_cookieOptions.SlidingExpiration || (decodedValue != null && decodedValue.ExpireDate > now && (decodedValue.ExpireDate - now).TotalSeconds > (_cookieOptions.Timeout * 60) / 2))
                {
                    return;
                }
            }

            // Resets cookie expiration time
            _cookieOptions.Expires = DateTime.UtcNow.AddSeconds(_cookieOptions.Timeout);

            // Appends the new cookie
            var data = new AnonymousIdData(anonymousId, _cookieOptions.Expires.Value.DateTime);
            encodedValue = AnonymousIdEncoder.Encode(data);
            httpContext.Response.Cookies.Append(_cookieOptions.Name, encodedValue, _cookieOptions);
        }

        public static void ClearAnonymousId(HttpContext httpContext, AnonymousIdCookieOptions cookieOptions)
        {
            if (!string.IsNullOrWhiteSpace(httpContext.Request.Cookies[cookieOptions.Name]))
            {
                httpContext.Response.Cookies.Delete(cookieOptions.Name);
            }
        }
    }
}