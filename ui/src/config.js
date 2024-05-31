function IsDebug() {
  if (import.meta.env.DEV)
    return true;
  return false;
}
function GetResourcesPath() {
  if (this.IsDebug())
    return "extraResources";
  return process.resourcesPath;
}

export default {
  MinRequiredDaemonVer: "3.14.2",

  MinimizedUIWidth: 320,
  MaximizedUIWidth: 800,
  UpdateWindowWidth: 600,

  // shellOpenExternal(...) allows only URLs started with this prefix
  URLsAllowedPrefixes: ["https://privateline.io/"],
  URLApps: "https://www.ivpn.net/apps/",

  IsDebug,
  GetResourcesPath,
};
