using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using SMBLibrary.Client;

namespace SMBLibrary.SMBManager
{
    public class SMBManager
    {
        private SMB2Client client;
        private SMB2FileStore fileStore;

        /// <summary>
        /// Внешний метод авторизации.
        /// </summary>
        public Func<AuthData> AuthFunc { get; set; }

        public SMBManager()
        {
            client = new SMB2Client();
        }

        /// <summary>
        /// Получение ip хоста.
        /// </summary>
        /// <returns>IP хоста</returns>
        public string GetLocalHostIp()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            return ip.Address.ToString();
                        }
                    }
                }
            }

            throw new Exception();
        }

        /// <summary>
        /// Получение списка всех доступных хостов.
        /// </summary>
        /// <returns>IEnumerable с хостами.</returns>
        /// Шинда не может в ведроид. Только Samba шаринг может помочь.
        public IEnumerable<Task<Server>> ScanNetworkAsync(CancellationToken cancellationToken)
        {
            string ipHost = GetLocalHostIp();
            var ipParts = ipHost.Split('.');
            var ipBase = ipParts[0] + "." + ipParts[1] + "." + ipParts[2] + ".";

            for (int i = 1; i <= 254; i++)
            {
                if (cancellationToken.IsCancellationRequested == true)
                {
                    break;
                }

                string ip = ipBase + i.ToString();

                if (ip != ipHost)   // TODO: Разбить на задачи.
                {
                    var task = Task.Run(new Func<Server>(() =>
                    {
                        var ping = new Ping();
                        var result = ping.Send(ip, 100);

                        if (result.Status == IPStatus.Success)
                        {
                            var host = GetHostInfo(result);

                            return host;
                        }
                        else
                        {
                            return null;
                        }
                    }));
                    yield return task;
                }
            }
        }

        /// <summary>
        /// Получение информации о хосте.
        /// </summary>
        /// <param name="result">Результат пинга хоста.</param>
        /// <returns>Информация.</returns>
        private Server GetHostInfo(PingReply result)
        {
            var host = new Server
            {
                Path = result.Address.ToString()
            };

            try
            {
                IPHostEntry hostEntry = Dns.GetHostEntry(host.Path);
                host.Name = hostEntry.HostName;
            }
            catch (Exception)
            {
                return null;
            }

            return host;
        }

        /// <summary>
        /// Подключение к серверу.
        /// </summary>
        /// <param name="server">Сервер.</param>
        /// <returns>Ф</returns>
        public Task Connect(Server server)
        {
            return Task.Run(async () =>
            {
                try
                {
                    IPAddress.TryParse(server.Path, out IPAddress address);
                    client.Connect(address, SMBTransportType.DirectTCPTransport, 1488);
                }
                catch (InvalidOperationException)
                {
                    Auth();
                    await Connect(server);
                }
                catch (Exception)
                {

                }
            });
        }

        /// <summary>
        /// Получение коллекции шар сервера.
        /// </summary>
        /// <param name="server">Сервер.</param>
        /// <returns>Коллекция шар.</returns>
        public Task<IEnumerable<FileDirectory>> GetShares(Server server)
        {
            return Task.Run(async () =>
            {
                try
                {
                    var shares = client.ListShares(out NTStatus status);
                    var shareList = new List<FileDirectory>();

                    foreach (var item in shares)
                    {
                        var share = new FileDirectory();
                        share.Path = $@"{server.Path}\{item}";
                        share.Mode = FileDirectoryModes.Share;
                        share.File = null;
                        share.Extension = null;
                        shareList.Add(share);
                    }

                    return shareList as IEnumerable<FileDirectory>;
                }
                catch (InvalidOperationException)
                {
                    Auth();
                    return await GetShares(server);
                }
            });
        }

        /// <summary>
        /// Получение коллекции файлов и папок.
        /// </summary>
        /// <param name="path">Путь.</param>
        /// <returns>Коллекция.</returns>
        public Task<IEnumerable<FileDirectory>> GetFilesDirectories(string path)
        {
            return Task.Run(async () =>
            {
                List<FileDirectory> pathList = new List<FileDirectory>();
                List<QueryDirectoryFileInformation> directoryInfo = new List<QueryDirectoryFileInformation>();

                NTStatus cf = NTStatus.STATUS_SUCCESS;
                NTStatus qd = NTStatus.STATUS_SUCCESS;

                try
                {
                    fileStore = client.TreeConnect(PathCutter.GetShare(path), out NTStatus shareStatus) as SMB2FileStore;

                    AccessMask accessMask = (AccessMask)(DirectoryAccessMask.FILE_LIST_DIRECTORY | DirectoryAccessMask.FILE_TRAVERSE | DirectoryAccessMask.SYNCHRONIZE);
                    ShareAccess shareAccess = ShareAccess.Read | ShareAccess.Write;
                    CreateOptions createOptions = CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT;
                    cf = fileStore.CreateFile(out object handle, out FileStatus createStatus, PathCutter.GetShareEmptyPath(path), accessMask, 0, shareAccess, CreateDisposition.FILE_OPEN, createOptions, null);
                    if (cf == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (cf != NTStatus.STATUS_SUCCESS) throw new Exception(cf.ToString());

                    qd = fileStore.QueryDirectory(out List<QueryDirectoryFileInformation> dirInfo, handle, "*", FileInformationClass.FileFullDirectoryInformation);
                    if (qd == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (qd != NTStatus.STATUS_NO_MORE_FILES) throw new Exception(qd.ToString());

                    fileStore.CloseFile(handle);
                    fileStore.Disconnect();

                    foreach (var item in dirInfo)
                    {
                        var filedir = new FileDirectory();
                        filedir.Path = $@"{path}\{(item as FileFullDirectoryInformation).FileName}";
                        filedir.Mode = ((item as FileFullDirectoryInformation).FileAttributes == SMBLibrary.FileAttributes.Directory) ? FileDirectoryModes.Directory : FileDirectoryModes.File;
                        filedir.File = (filedir.Mode == FileDirectoryModes.File) ? filedir.Path.Split('\\').Last() : null;
                        filedir.Extension = (filedir.Mode == FileDirectoryModes.File) ? filedir.Path.Split('.').Last() : null;
                        pathList.Add(filedir);
                    }

                    return pathList as IEnumerable<FileDirectory>;
                }
                catch (SMBAccessDeniedException)
                {
                    Auth();
                    return await GetFilesDirectories(path);
                }
                catch (InvalidOperationException)
                {
                    Auth();
                    return await GetFilesDirectories(path);
                }
            });
        }

        /// <summary>
        /// Удаление файла.
        /// </summary>
        /// <param name="path">Путь</param>
        /// <returns></returns>
        public Task DeleteFileAsync(string path) //TODO: Расширить функционал и для папочек.
        {
            return Task.Run(async () =>
            {
                NTStatus cf = NTStatus.STATUS_SUCCESS;
                NTStatus si = NTStatus.STATUS_SUCCESS;

                try
                {
                    fileStore = client.TreeConnect(PathCutter.GetShare(path), out NTStatus shareStatus) as SMB2FileStore;

                    cf = fileStore.CreateFile(out object handle, out FileStatus createStatus, PathCutter.GetShareEmptyPath(path), AccessMask.GENERIC_ALL, 0, ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE, null);
                    if (cf == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (cf != NTStatus.STATUS_SUCCESS) throw new Exception(cf.ToString());

                    var fileInformation = new FileDispositionInformation();
                    fileInformation.DeletePending = true;
                    si = fileStore.SetFileInformation(handle, fileInformation);
                    if (si == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (si != NTStatus.STATUS_SUCCESS) throw new Exception(si.ToString());

                    fileStore.CloseFile(handle);
                    fileStore.Disconnect();
                }
                catch (SMBAccessDeniedException)
                {
                    Auth();
                    await DeleteFileAsync(path);
                }
                catch (InvalidOperationException)
                {
                    Auth();
                    await DeleteFileAsync(path);
                }
            });
        }


        /// <summary>
        /// Проверка существования файла.
        /// </summary>
        /// <param name="path">Путь.</param>
        /// <returns>Флаг проверки.</returns>
        public Task<bool> IsExistsAsync(string path) //TODO: Расширить функционал и для папочек.
        {
            return Task.Run(async () =>
            {
                NTStatus cf = NTStatus.STATUS_SUCCESS;

                try
                {
                    fileStore = client.TreeConnect(PathCutter.GetShare(path), out NTStatus shareStatus) as SMB2FileStore;

                    cf = fileStore.CreateFile(out object handle, out FileStatus createStatus, PathCutter.GetShareEmptyPath(path), AccessMask.GENERIC_ALL, 0, ShareAccess.Read, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE, null);
                    if (cf == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (cf != NTStatus.STATUS_SUCCESS) throw new Exception(cf.ToString());

                    fileStore.CloseFile(handle);
                    fileStore.Disconnect();

                    if (createStatus == FileStatus.FILE_EXISTS || createStatus == FileStatus.FILE_OPENED)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                catch (SMBAccessDeniedException)
                {
                    Auth();
                    return await IsExistsAsync(path);
                }
                catch (InvalidOperationException)
                {
                    Auth();
                    return await IsExistsAsync(path);
                }
            });
        }

        /// <summary>
        /// Чтение файла.
        /// </summary>
        /// <param name="path">Путь.</param>
        /// <returns></returns>
        public Task LoadFileAsync(string sourcePath, string destinationPath)
        {
            return Task.Run(async () =>
            {
                NTStatus cf = NTStatus.STATUS_SUCCESS;
                NTStatus gi = NTStatus.STATUS_SUCCESS;
                NTStatus rf = NTStatus.STATUS_SUCCESS;

                try
                {
                    fileStore = client.TreeConnect(PathCutter.GetShare(sourcePath), out NTStatus shareStatus) as SMB2FileStore;

                    cf = fileStore.CreateFile(out object handle, out FileStatus fileStatus, PathCutter.GetShareEmptyPath(sourcePath), AccessMask.GENERIC_ALL, 0, ShareAccess.Read, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE, null);
                    if (cf == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (cf != NTStatus.STATUS_SUCCESS) throw new Exception(cf.ToString());

                    gi = fileStore.GetFileInformation(out FileInformation info, handle, FileInformationClass.FileStandardInformation);
                    if (gi == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (gi != NTStatus.STATUS_SUCCESS) throw new Exception(gi.ToString());

                    var size = (int)(info as FileStandardInformation).EndOfFile;

                    rf = Read(out byte[] buffer, handle, size);
                    if (rf == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (rf != NTStatus.STATUS_SUCCESS) throw new Exception(rf.ToString());

                    fileStore.CloseFile(handle);
                    fileStore.Disconnect();

                    using (var file = File.OpenWrite(destinationPath))
                    {
                        await file.WriteAsync(buffer, 0, buffer.Length);
                        file.Close();
                    }
                }
                catch (SMBAccessDeniedException)
                {
                    Auth();
                    await LoadFileAsync(sourcePath, destinationPath);
                }
                catch (InvalidOperationException)
                {
                    Auth();
                    await LoadFileAsync(sourcePath, destinationPath);
                }
            });
        }

        private NTStatus Read(out byte[] buffer, object handle, int length)
        {
            long read = 0;
            int maxOffset = (int)fileStore.MaxReadSize;
            buffer = new byte[length];

            while (read != length)
            {
                var rf = fileStore.ReadFile(out byte[] chunk, handle, read, maxOffset);

                if (rf != NTStatus.STATUS_SUCCESS)
                {
                    buffer = null;
                    return rf;
                }

                Buffer.BlockCopy(chunk, 0, buffer, (int)read, chunk.Length);

                read += chunk.Length;
            }

            return NTStatus.STATUS_SUCCESS;

        }

        /// <summary>
        /// Отправка файла.
        /// </summary>
        /// <param name="sourcePath">Исходный файл.</param>
        /// <param name="destinationPath">Файл назначения</param>
        /// <returns></returns>
        public Task UploadFileAsync(string sourcePath, string destinationPath)
        {
            return Task.Run(async () =>
            {
                NTStatus cf = NTStatus.STATUS_SUCCESS;
                NTStatus sf = NTStatus.STATUS_SUCCESS;
                NTStatus wf = NTStatus.STATUS_SUCCESS;

                try
                {
                    byte[] buffer;

                    using (var file = File.OpenRead(sourcePath))
                    {
                        buffer = new byte[file.Length];

                        await file.ReadAsync(buffer, 0, (int)file.Length);
                        file.Close();
                    }

                    fileStore = client.TreeConnect(PathCutter.GetShare(destinationPath), out NTStatus shareStatus) as SMB2FileStore;

                    cf = fileStore.CreateFile(out object handle, out FileStatus fileStatus, PathCutter.GetShareEmptyPath(destinationPath), AccessMask.GENERIC_ALL, 0, ShareAccess.Write, CreateDisposition.FILE_OPEN_IF, CreateOptions.FILE_NON_DIRECTORY_FILE, null);

                    var info = new FileEndOfFileInformation();
                    info.EndOfFile = buffer.Length;

                    sf = fileStore.SetFileInformation(handle, info);
                    if (sf == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (sf != NTStatus.STATUS_SUCCESS) throw new Exception(sf.ToString());

                    wf = Write(buffer, handle);
                    if (wf == NTStatus.STATUS_ACCESS_DENIED) throw new SMBAccessDeniedException();
                    if (wf != NTStatus.STATUS_SUCCESS) throw new Exception(wf.ToString());

                    fileStore.CloseFile(handle);
                    fileStore.Disconnect();
                }
                catch (SMBAccessDeniedException)
                {
                    Auth();
                    await UploadFileAsync(sourcePath, destinationPath);
                }
                catch (InvalidOperationException)
                {
                    Auth();
                    await UploadFileAsync(sourcePath, destinationPath);
                }
            });
        }

        private NTStatus Write(byte[] buffer, object handle)
        {
            int write = 0;
            int maxOffset = 65536;

            while (write != buffer.Length)
            {
                if (write + maxOffset > buffer.Length)
                {
                    maxOffset = buffer.Length - write;
                }

                byte[] chunk = new byte[maxOffset];

                for (int i = 0; i < maxOffset; i++)
                {
                    chunk[i] = buffer[i + write];
                }

                var wf = fileStore.WriteFile(out int countOfBytes, handle, write, chunk);

                if (wf != NTStatus.STATUS_SUCCESS)
                {
                    return wf;
                }

                write += maxOffset;
            }

            return NTStatus.STATUS_SUCCESS;
        }

        /// <summary>
        /// Отключение от сервера.
        /// </summary>
        /// <returns></returns>
        public Task Disconnect()
        {
            return Task.Run(() =>
            {
                try
                {
                    client.Disconnect();
                }
                catch (InvalidOperationException)
                {
                }
            });
        }

        /// <summary>
        /// Деавторизация.
        /// </summary>
        /// <returns></returns>
        public Task Logoff()
        {
            return Task.Run(() =>
            {
                try
                {
                    client.Logoff();
                }
                catch (InvalidOperationException)
                {
                }
            });
        }

        /// <summary>
        /// Авторизация.
        /// </summary>
        private void Auth()
        {
            var data = AuthFunc();

            if (data.Cancel == true) throw new SMBCancelAuthException();

            var res = client.Login(data.Domain, data.Login, data.Password);

            switch (res)
            {
                case NTStatus.STATUS_SUCCESS:
                    break;
                case NTStatus.STATUS_LOGON_FAILURE:
                    Auth();
                    break;
                case NTStatus.STATUS_ACCESS_DENIED:
                    Auth();
                    break;
                default:
                    throw new Exception(res.ToString());
            }
        }
    }
}
