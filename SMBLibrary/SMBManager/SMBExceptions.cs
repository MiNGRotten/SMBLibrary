using System;
using System.Collections.Generic;
using System.Text;

namespace SMBLibrary.SMBManager
{
    /// <summary>
    /// Остановка SMB действия.
    /// </summary>
    public class SMBCancelException : Exception
    {
    }

    public class SMBAccessDeniedException : Exception
    {
    }

    public class SMBCancelAuthException : Exception
    {
    }
}
