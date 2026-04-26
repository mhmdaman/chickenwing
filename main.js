const { app, BrowserWindow, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let tray = null;
let pythonProcess = null;

function startPythonBackend() {
  const isWin = process.platform === 'win32';
  let binaryName = isWin ? 'packet_engine.exe' : 'packet_engine';
  let binaryPath = path.join(__dirname, 'backend', binaryName);
  let workingDir = path.join(__dirname, 'backend');

  if (app.isPackaged) {
    binaryPath = binaryPath.replace('app.asar', 'app.asar.unpacked');
    workingDir = workingDir.replace('app.asar', 'app.asar.unpacked');
  }

  if (process.platform === 'darwin') {
    // Run binary with sudo via osascript
    const command = `do shell script "cd '${workingDir}' && ./${binaryName} > /tmp/packet_sniffer.log 2>&1" with administrator privileges`;

    try {
      const appleScript = spawn('osascript', ['-e', command], {
        detached: true,
        stdio: 'ignore'
      });
      appleScript.unref();
    } catch (err) {
      console.error('Failed to launch backend:', err);
    }
  } else if (process.platform === 'win32') {
    // On Windows, we spawn it. User should run app as Admin for raw socket access.
    pythonProcess = spawn(binaryPath, [], {
      cwd: workingDir,
      windowsHide: true
    });
    
    pythonProcess.stdout.on('data', (data) => console.log(`Backend: ${data}`));
    pythonProcess.stderr.on('data', (data) => console.error(`Backend Error: ${data}`));
  } else {
    // Fallback for other platforms
    pythonProcess = spawn(binaryPath);
    pythonProcess.stdout.on('data', (data) => console.log(`Backend: ${data}`));
    pythonProcess.stderr.on('data', (data) => console.error(`Backend Error: ${data}`));
  }
}

function createWindow() {
  const isMac = process.platform === 'darwin';
  
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    resizable: true,
    maximizable: true,
    fullscreenable: true,
    show: false,
    frame: !isMac, // Use custom title bar on Mac, default on Win for consistency or keep it hidden if we have custom UI
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    titleBarStyle: isMac ? 'hiddenInset' : 'default',
    trafficLightPosition: isMac ? { x: 20, y: 24 } : null,
    backgroundColor: '#030405',
    vibrancy: isMac ? 'under-window' : null,
    visualEffectState: 'active'
  });

  // Load the app
  if (app.isPackaged) {
    mainWindow.loadFile(path.join(__dirname, 'dist/index.html'));
  } else {
    const loadURL = () => {
      mainWindow.loadURL('http://localhost:5173').catch(() => {
        setTimeout(loadURL, 1000);
      });
    };
    loadURL();
  }

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });
}

function createTray() {
  const iconPath = path.join(__dirname, 'icon.png');
  const icon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
  tray = new Tray(icon);

  const contextMenu = Menu.buildFromTemplate([
    { label: 'Show Dashboard', click: () => mainWindow.show() },
    { type: 'separator' },
    {
      label: 'Quit Chickenwing', click: () => {
        app.isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setToolTip('Chickenwing');
  tray.setContextMenu(contextMenu);
}

app.whenReady().then(() => {
  startPythonBackend();
  createWindow();
  createTray();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
  else mainWindow.show();
});

app.on('will-quit', () => {
  if (pythonProcess) {
    pythonProcess.kill();
  }
});
