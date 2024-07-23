import { app } from "electron";
import { Platform, PlatformEnum } from "@/platform/platform";

// initialize application auto-launcher
var AutoLaunch = require("auto-launch");
let launcherOptions = { name: "privateLINE", isHidden: true }; // isHidden is in use by Windows and Linux implementation (see function: WasOpenedAtLogin())
var autoLauncher = null;

if (Platform() === PlatformEnum.Linux) {
  const fs = require("fs");
  let binaryPath = process.execPath;
  if (fs.existsSync(binaryPath)) launcherOptions.path = binaryPath;
  else launcherOptions = null;
}

if (launcherOptions != null) autoLauncher = new AutoLaunch(launcherOptions);

function AutoLaunchIsInitialized() {
  return autoLauncher != null;
}

export function WasOpenedAtLogin() {
  try {
    if (Platform() === PlatformEnum.macOS) {
      let loginSettings = app.getLoginItemSettings();
      return loginSettings.wasOpenedAtLogin;
    }
    return app.commandLine.hasSwitch("hidden");
  } catch {
    return false;
  }
}

export async function AutoLaunchIsEnabled() {
  if (!AutoLaunchIsInitialized()) return null;
  try {
    return await autoLauncher.isEnabled();
  } catch (err) {
    console.error("Error obtaining 'LaunchAtLogin' value: ", err);
    return null;
  }
}

export async function AutoLaunchSet(isEnabled) {
  if (!AutoLaunchIsInitialized()) return;
  if (isEnabled) await autoLauncher.enable();
  else await autoLauncher.disable();
}
