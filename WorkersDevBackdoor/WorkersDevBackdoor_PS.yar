rule WorkersDevBackdoor_PS {

	meta:
		author = "RussianPanda"
		decription = "Detects WorkersDevBackdoor PowerShell script"
		date = "12/15/2023"

	strings:
		$s1 = "sleep" wide
		$s2 = "convertto-securestring" wide
		$s3 = "System.Drawing.dll" wide
		$s4 = "System.Web.Extensions.dll" wide
		$s5 = "System.Windows.Forms.dll" wide
		$s6 = "CSharp" wide
		
	condition:
		all of ($s*) and filesize < 200KB
}
