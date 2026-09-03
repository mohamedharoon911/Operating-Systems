Dim WshShell, FSO, ScriptDir
Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
ScriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = ScriptDir
WshShell.Run Chr(34) & ScriptDir & "\OSentinel.bat" & Chr(34), 0, False
