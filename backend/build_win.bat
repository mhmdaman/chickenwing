@echo off
echo Building Chickenwing Packet Engine for Windows...
echo Ensuring dependencies are installed...
pip install flask flask-cors scapy pyinstaller

echo Running PyInstaller...
pyinstaller --onefile --name packet_engine --clean packet.py

echo.
echo Done! The binary is in the 'dist' folder.
echo Copy 'dist/packet_engine.exe' to the 'backend' folder of the project.
pause
