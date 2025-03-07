function IsDebug() {
  if (import.meta.env.DEV) return true;
  return false;
}
function GetResourcesPath() {
  if (this.IsDebug()) return "extraResources";
  return process.resourcesPath;
}

export default {
  MinRequiredDaemonVer: "1.1.0",

  MinimizedUIWidth: 420,
  MaximizedUIWidth: 800,
  UpdateWindowWidth: 600,

  // shellOpenExternal(...) allows only URLs started with this prefix
  URLsAllowedPrefixes: [
    "https://privateline.io/",
    "https://sso.privateline.io/",
    "https://sso.privateline.dev/",
    "https://account.privateline.io",
    "https://meet.privateline.network",
    "x-apple.systempreferences:",
  ],
  URLApps: "https://privateline.io/downloads/",

  IsDebug,
  GetResourcesPath,
};
