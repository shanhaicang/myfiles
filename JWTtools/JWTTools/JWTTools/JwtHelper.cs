using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTTools
{
    public class JwtHelper
    {
        public static string ClaimName = string.Empty;
        public static string ClaimRole = string.Empty;
        public static string JwtRegis = string.Empty;
        public JwtHelper(string SecretKey,string Issuer, string Audience,string jwtRegis, string claimName,string claimRole)
        {
            JwtModel.SecretKey= SecretKey;
            JwtModel.Issuer= Issuer;
            JwtModel.Audience= Audience;
            ClaimName = claimName;
            ClaimRole = claimRole;
            JwtRegis = jwtRegis;
        }
        public string CreateToken(Dictionary<string, string> Dict = null)
        {
            var claims = new Claim[]
            {
                new Claim(ClaimTypes.Name,ClaimName),
                new Claim(ClaimTypes.Role,ClaimRole),
                new Claim(JwtRegisteredClaimNames.Jti,JwtRegis)
            };
            var claList = claims.ToList();
            if (Dict != null)
            {
                foreach (var item in Dict)
                {
                    claList.Add(new Claim(item.Key, item.Value));
                }
            }
            claims = claList.ToArray();
            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtModel.SecretKey));
            //选择加密方式
            var algorithm = SecurityAlgorithms.HmacSha256;
            //凭据
            var signingCredentials = new SigningCredentials(secretKey, algorithm);
            var jwtSecurityToken = new JwtSecurityToken(JwtModel.Issuer,
                JwtModel.Audience,
                claims,
                DateTime.Now,
                DateTime.Now.AddDays(1), 
                signingCredentials);
            //把token转换为string
            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            return token;
        }

        //解析token
        public string AnalysisToken(string token,string claimType)
        {
            string tokenStr = token.Replace("Bearer ", "");
            var handler = new JwtSecurityTokenHandler();
            var payload = handler.ReadJwtToken(tokenStr).Payload;
            var claims = payload.Claims;
            return claims.First(i=>i.Type==claimType).Value;
        }
    }
}