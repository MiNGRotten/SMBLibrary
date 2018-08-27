using System;
using System.Collections.Generic;
using System.Text;

namespace SMBLibrary.SMBManager
{
    public class AuthData
    {
        public string Login { get; set; }
        public string Password { get; set; }
        public string Domain { get; set; }
        public bool Cancel { get; set; }
    }
}
