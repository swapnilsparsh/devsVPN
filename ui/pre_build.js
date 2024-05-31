console.log("[ ] Preparing build...");

const os = require("os");

// PLATFORM SPECIFIC STYLE LOADER
console.log("\n[ ] Copying platform specific style loader...");
var styleLoaderFile = __dirname + "/src/main_style.js";
var styleLoaderFilePlatform =
  __dirname + "/src/main_style_" + os.platform() + ".js";

console.log("Using style loader script: " + styleLoaderFilePlatform);

var fs = require("fs");
if (fs.existsSync(styleLoaderFilePlatform)) {
  fs.copyFileSync(styleLoaderFilePlatform, styleLoaderFile);
} else {
  var mainStyleFileNotExists =
    " *** ERROR: FILE NOT EXISTS: *** '" +
    styleLoaderFilePlatform +
    "'. Is [" +
    os.platform() +
    "] platform supported? ";

  console.error("");
  console.error(mainStyleFileNotExists);
  console.error();

  throw mainStyleFileNotExists;
}

console.log("\n[ ] Build preparation finished.\n");
