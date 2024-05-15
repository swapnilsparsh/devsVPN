import { createApp } from "vue";

import App from "./App.vue";
import router from "./router";
import store from "./store";

const sender = window.ipcSender;

import "@/main_style_win32.js";

const app = createApp(App);
app.use(store);
app.use(router);
app.mount("#app");

// Waiting for "change view" requests from main thread
const ipcRenderer = sender.GetSafeIpcRenderer();
ipcRenderer.on("main-change-view-request", (event, arg) => {
  router.push(arg);
});

// After initialized, ask main thread about initial route
setTimeout(async () => {
  let initRouteArgs = await sender.GetInitRouteArgs();
  if (initRouteArgs != null) router.push(initRouteArgs);
}, 0);
