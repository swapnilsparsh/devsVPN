import { createRouter, createWebHashHistory } from "vue-router";
import Main from "../views/Component-Main.vue";
import AccountLimit from "../views/AccountLimit.vue";
import Settings from "../views/Component-Settings.vue";
import Update from "../views/dialogs/Dlg-Update.vue";
import VpnWizardExample from "../components/VpnWizardExample.vue";

const mainRoutes = [
  {
    path: "/",
    name: "Main",
    component: Main,
  },
  {
    path: "/account_limit",
    name: "AccountLimit",
    component: AccountLimit,
  },
  {
    path: "/settings/:view",
    name: "settings",
    component: Settings,
  },
  {
    path: "/test",
    name: "Test",
    // route level code-splitting
    // this generates a separate chunk (about.[hash].js) for this route
    // which is lazy-loaded when the route is visited.
    component: () =>
      import("../views/Component-Test.vue"),
  },
];
const forbiddenToChangeRouteFrom = [
  {
    path: "/update",
    name: "Update",
    component: Update,
  },
  {
    path: "/vpnwizard",
    name: "VpnWizardExample",
    component: VpnWizardExample,
  },
];

const routes = mainRoutes.concat(forbiddenToChangeRouteFrom);

const router = createRouter({
  history: createWebHashHistory(),
  base: import.meta.env.BASE_URL, // process.env.BASE_URL,
  routes,
});

router.beforeEach((to, from, next) => {
  // check if route allowed
  for (let route of forbiddenToChangeRouteFrom) {
    if (from.path === route.path) {
      next(false);
      return;
    }
  }
  // allow route
  next();
});

export default router;
