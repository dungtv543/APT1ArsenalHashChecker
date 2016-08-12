using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
//using Newtonsoft.Json;
using System.IO;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
namespace CheckHash
{

    public class Program
    {
        //List<FileEntity> FileEntities;
        ConcurrentBag<FileInfo> Results = new ConcurrentBag<FileInfo>();
        string ResultFile;
        List<string> lines;
        public Program()
        {
            ResultFile = String.Format("{0:yyyyMMddhhmmss}__Result Scan.txt", DateTime.Now);
            using (StreamWriter w = File.AppendText(ResultFile))
            {
                w.WriteLine("Time Start Scan :" + DateTime.Now.ToString());
                w.WriteLine("Computer Name : " + Environment.MachineName);

                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        w.WriteLine(ip.ToString());
                    }
                }
            }
        }
        public static void Main(string[] args)
        {
            Program Program = new Program();

            Program.ReadFile();
            Program.Scan();
            Program.Delete();
        }

        public void ReadFile()
        {
            lines = System.IO.File.ReadAllLines("db.txt").ToList();

        }

        public void Scan()
        {
            string[] drives = System.IO.Directory.GetLogicalDrives();

            foreach (string drive in drives)
            {
                Console.WriteLine("Scanning...");
                DirSearch(drive);
            }

            string Infected = String.Format("{0:yyyyMMddhhmmss}__Infected.txt", DateTime.Now);
            File.WriteAllLines(Infected, Results.Select(r => r.FullName).ToArray());
        }

        public void Delete()
        {
            using (StreamWriter w = File.AppendText(ResultFile))
            {
                foreach (FileInfo FileInfo in Results)
                {
                    try
                    {
                        foreach (var process in Process.GetProcessesByName(FileInfo.Name))
                        {
                            process.Kill();
                        }
                        FileInfo.Delete();
                        w.WriteLine(FileInfo.FullName + " : Deleted");
                    }
                    catch (Exception ex)
                    {
                        w.WriteLine(FileInfo.FullName + " : Error - " + ex.Message);
                    }
                }
            }
        }

        public void DirSearch(string dir)
        {
            try
            {
                Console.WriteLine(dir);

                string[] files = Directory.GetFiles(dir);
                Parallel.ForEach(files, (file) =>
                {
                    MD5 MD5 = MD5.Create();
                    FileInfo FileInfo = new FileInfo(file);
                    if (FileInfo.Exists)
                    {
                        try
                        {
                            using (var stream = File.OpenRead(file))
                            {
                                StringBuilder FileMD5 = new StringBuilder();
                                byte[] MD5Hash = MD5.ComputeHash(stream);
                                StringBuilder sMD5 = new StringBuilder();
                                for (int i = 0; i < MD5Hash.Length; i++)
                                    sMD5.Append(MD5Hash[i].ToString("X2").ToLower());
                               foreach(string line in lines)
                                {
                                    if (line.Equals(sMD5))
                                    {
                                        Results.Add(FileInfo);
                                        Console.WriteLine("Detected: %s", FileInfo);
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex);
                        }
                    }
                });
                foreach (string d in Directory.GetDirectories(dir))
                {
                    DirSearch(d);
                }

            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }

    public class FileEntity
    {
        public string Name { get; set; }
        public string MD5 { get; set; }
    }
}
