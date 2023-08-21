using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWTTools
{
    public static class JwtModel
    {
       public static string SecretKey { get; set; } = string.Empty;
        public static string Issuer { get; set; } = string.Empty;
       public static string Audience { get; set; } = string.Empty;
    }
}
