using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace encrypTools
{
    public class EncrypTools
    {
        private readonly string _publicKey;
        private readonly string _privateKey;

        public EncrypTools()
        {
            using (var rsa = RSA.Create())
            {
               
                var filedic = System.AppDomain.CurrentDomain.BaseDirectory;
                var path = filedic + "\\RSA";
                var publickey = path + "\\publickey.txt";
                var privatekey = path + "\\privatekey.txt";
                if (!Directory.Exists(path))
                {
                    DirectoryInfo directoryInfo = new DirectoryInfo(path);
                    directoryInfo.Create();
                    _publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
                    _privateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
                    if(!Directory.Exists(publickey)) {
                        WriteFile(publickey, _publicKey);
                    }
                    if(!Directory.Exists(privatekey)) {
                        WriteFile(privatekey, _privateKey);
                    }
                }
                else
                {
                    _publicKey = ReadFile(publickey);
                    _privateKey = ReadFile(privatekey);
                }
            }
        }
        public string ReadFile(string filepath)
        {
            StringBuilder data = new StringBuilder();
            using (FileStream fs = new FileStream(filepath, FileMode.OpenOrCreate, FileAccess.Read))
            {//在using中创建FileStream对象fs，然后执行大括号内的代码段，
             //执行完后，释放被using的对象fs（后台自动调用了Dispose）
                byte[] vs = new byte[1024];//数组大小根据自己喜欢设定，太高占内存，太低读取慢。
                while (true) //因为文件可能很大，而我们每次只读取一部分，因此需要读很多次
                {
                    int r = fs.Read(vs, 0, vs.Length);
                    string s = Encoding.UTF8.GetString(vs, 0, r);
                    data.Append(s);
                    if (r == 0) //当读取不到，跳出循环
                    {
                        break;
                    }
                }
            }
            return data.ToString();
        }
        public void WriteFile(string filepath,string key)
        {
            using (FileStream fs = new FileStream(filepath, FileMode.OpenOrCreate, FileAccess.Write))
            {
                byte[] buffer = Encoding.UTF8.GetBytes(key);
                fs.Write(buffer, 0, buffer.Length);
            }
        }
        /// <summary>
        /// MD5加密
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public string EncrypToMd5(string input)
        {
            var md5 = MD5.Create();
            var bytes = Encoding.UTF8.GetBytes(input);
            var hashbyte = md5.ComputeHash(bytes);
            StringBuilder sb = new StringBuilder();
            for (int i = 0;i<hashbyte.Length; i++)
            {
                sb.Append(hashbyte[i].ToString("x2"));
            }
            return sb.ToString();
        }
        /// <summary>
        /// SHA256加密
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public string EncrypToSh256(string input)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            byte[] hash = SHA256.Create().ComputeHash(bytes);

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                builder.Append(hash[i].ToString("x2"));
            }
            return builder.ToString();
        }

        /// <summary>
        /// RSA加密
        /// </summary>
        public string EncrypToRSA(string plaintext)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(_publicKey), out _);

                var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                var encryptedBytes = rsa.Encrypt(plaintextBytes, RSAEncryptionPadding.OaepSHA256);

                return Convert.ToBase64String(encryptedBytes);
            }
        }

        public string RSADecrypt(string ciphertext)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(_privateKey), out _);

                var ciphertextBytes = Convert.FromBase64String(ciphertext);
                var decryptedBytes = rsa.Decrypt(ciphertextBytes, RSAEncryptionPadding.OaepSHA256);

                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }

    }
}