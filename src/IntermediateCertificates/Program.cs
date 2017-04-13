using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace IntermediateCertificates
{
	class Program
	{
		private const string userRegKey = @"Software\Microsoft\SystemCertificates\CA\Certificates";
		static void Main(string[] args)
		{
			CertificateStorePath[] paths =
			{
				new CertificateStorePath()
				{
					Name = "Local Computer",
					RegKey = userRegKey,
					Hive = RegistryHive.LocalMachine
				},
				new CertificateStorePath()
				{
					Name = "SYSTEM Account (LocalSystem)",
					RegKey = "S-1-5-18\\" + userRegKey,
					Hive = RegistryHive.Users
				},
				new CertificateStorePath()
				{
					 Name = $"Local User ({Environment.UserName})",
					 RegKey = userRegKey,
					 Hive = RegistryHive.CurrentUser
				}

			};

			foreach (CertificateStorePath path in paths)
			{
				Console.WriteLine($"Searching Intermediate Certificates for {path.Name}...");
				Console.WriteLine();
				Console.WriteLine();

				// Open the key.
				using (RegistryKey k = RegistryKey.OpenBaseKey(path.Hive, RegistryView.Registry64))
				{
					using (var basekey = k.OpenSubKey(path.RegKey))
					{
						string[] subkeys = basekey.GetSubKeyNames();
						foreach (var subkey in subkeys)
						{
							using (var sub = basekey.OpenSubKey(subkey))
							{
								var value = sub.GetValue("Blob");
								if (value is byte[])
								{
									// Load the certificate.
									X509Certificate2 cert = new X509Certificate2((byte[])value);
									Console.WriteLine($"Certificate [{subkey}]: Subject={cert.Subject}, Issuer={cert.Issuer}, Thumprint (SHA1)={cert.Thumbprint}");
									Console.WriteLine();
								}
							}
						}
					}
				}

				Console.WriteLine();
				Console.WriteLine();
				Console.WriteLine();
				Console.WriteLine();
			}


			Console.WriteLine("Press a key to exit.");
			Console.ReadKey();
		}


		private struct CertificateStorePath
		{
			public string Name { get; set; }
			public string RegKey { get; set; }
			public RegistryHive Hive { get; set; }
		}
	}
}