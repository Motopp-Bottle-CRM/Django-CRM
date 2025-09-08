# PowerShell script to run Django commands with proper virtual environment
$projectPath = "C:\Users\TinaShahedi\OneDrive - Motopp\Documents\Motopp internship\Django-CRM"
$pythonExe = "$projectPath\venv\Scripts\python.exe"

Set-Location $projectPath
& $pythonExe manage.py $args
