using System;

namespace SMBLibrary.SMBManager
{
    public class PathCutter
    {
        public static string GetServerPath(string path)
        {
            if (path.StartsWith(@"\\"))
            {
                int index = path.IndexOf('\\', 3);
                if (index > 0)
                {
                    var res = path.Substring(index);
                    return res;
                }
                else
                {
                    return String.Empty;
                }
            }
            return path;
        }

        public static string GetShareStarPath(string path)
        {
            string relativePath = GetServerPath(path);
            int index = relativePath.IndexOf('\\', 1);
            if (index > 0)
            {
                var res = relativePath.Substring(index + 1);
                return res;
            }
            else
            {
                return @"*";
            }
        }

        public static string GetShareEmptyPath(string path)
        {
            string relativePath = GetServerPath(path);
            int index = relativePath.IndexOf('\\', 1);
            if (index > 0)
            {
                var res = relativePath.Substring(index + 1);
                return res;
            }
            else
            {
                return @"";
            }
        }

        public static string GetShare(string path)
        {
            string relativePath = GetServerPath(path);
            if (relativePath.StartsWith(@"\"))
            {
                relativePath = relativePath.Substring(1);
            }

            int indexOfSeparator = relativePath.IndexOf(@"\");
            if (indexOfSeparator >= 0)
            {
                relativePath = relativePath.Substring(0, indexOfSeparator);
            }
            return relativePath;
        }
    }
}