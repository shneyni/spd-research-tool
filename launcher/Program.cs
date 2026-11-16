// Single-EXE launcher: extracts embedded payload (translated tool + drivers) on first run,
// installs the UNISOC/SPD drivers once (UAC prompt), then starts ResearchDownload.exe.
// Written for the C# 5 compiler that ships with .NET Framework 4.x (csc.exe), no SDK needed.
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Windows.Forms;
using Microsoft.Win32;

static class Program
{
    const string Version = "__VERSION__";           // replaced by the workflow
    const string AppName = "SPD_Research_Tool_HE";
    static readonly string[] Infs = { "sprdadb.inf", "sprdvcom.inf", "sprdvmdm.inf", "rdavcom.inf" };

    [STAThread]
    static int Main(string[] args)
    {
        try
        {
            if (args.Length > 0 && args[0] == "--install-drivers") return InstallDrivers();

            string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppName, Version);
            string appDir = Path.Combine(root, "app");
            if (!File.Exists(Path.Combine(root, ".ok")))
            {
                string tmp = root + ".tmp";
                if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
                if (Directory.Exists(root)) Directory.Delete(root, true);
                ExtractPayload(tmp, "app/");
                Directory.Move(tmp, root);
                File.WriteAllText(Path.Combine(root, ".ok"), Version);
            }

            if (!DriversPresent())
            {
                var psi = new ProcessStartInfo(Application.ExecutablePath, "--install-drivers");
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                try
                {
                    using (Process p = Process.Start(psi))
                    {
                        p.WaitForExit();
                        if (p.ExitCode != 0)
                            MessageBox.Show("התקנת הדרייברים לא הושלמה (קוד " + p.ExitCode + ").\nהתוכנה תיפתח, אך ייתכן שהמכשיר לא יזוהה.",
                                AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button1, MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign);
                    }
                }
                catch (System.ComponentModel.Win32Exception) { /* UAC declined */ }
            }

            var start = new ProcessStartInfo(Path.Combine(appDir, "ResearchDownload.exe"));
            start.WorkingDirectory = appDir;
            Process.Start(start);
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    static void ExtractPayload(string dest, string prefix)
    {
        using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
        using (var zip = new ZipArchive(s, ZipArchiveMode.Read))
        {
            string full = Path.GetFullPath(dest) + Path.DirectorySeparatorChar;
            foreach (ZipArchiveEntry e in zip.Entries)
            {
                if (!e.FullName.StartsWith(prefix, StringComparison.Ordinal) || e.Name.Length == 0) continue;
                string target = Path.GetFullPath(Path.Combine(dest, e.FullName.Substring(prefix.Length)));
                if (!target.StartsWith(full, StringComparison.OrdinalIgnoreCase)) continue;   // zip-slip guard
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                using (Stream o = File.Create(target)) using (Stream i = e.Open()) i.CopyTo(o);
            }
        }
    }

    static bool DriversPresent()
    {
        string repo = Path.Combine(Environment.SystemDirectory, "DriverStore", "FileRepository");
        foreach (string inf in Infs)
            if (Directory.GetDirectories(repo, inf + "_*").Length == 0) return false;
        return true;
    }

    // Runs elevated. Extracts drivers to a temp folder, stages+installs them with pnputil, sets the same
    // UsbFlags registry values the original installer (config.reg) sets.
    static int InstallDrivers()
    {
        string tmp = Path.Combine(Path.GetTempPath(), "spd_drv_" + Guid.NewGuid().ToString("N"));
        try
        {
            ExtractPayload(tmp, "drivers/");
            int worst = 0;
            foreach (string inf in Infs)
            {
                var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "pnputil.exe"),
                    "/add-driver \"" + Path.Combine(tmp, inf) + "\" /install");
                psi.UseShellExecute = false; psi.CreateNoWindow = true;
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit();
                    // 0 = ok, 3010 = ok (reboot), 259 = nothing more to install
                    if (p.ExitCode != 0 && p.ExitCode != 3010 && p.ExitCode != 259) worst = p.ExitCode;
                }
            }
            using (RegistryKey k = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\UsbFlags"))
                foreach (string n in new[] { "IgnoreHWSerNum17824D01", "IgnoreHWSerNum17824D00", "IgnoreHWSerNum17824026" })
                    k.SetValue(n, new byte[] { 1 }, RegistryValueKind.Binary);
            return worst;
        }
        finally { try { Directory.Delete(tmp, true); } catch { } }
    }
}
