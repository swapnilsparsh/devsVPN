<template>
  <div>
    <svg
      v-if="platform == PlatformEnum.Linux"
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M10.53 2.47C10.8232 2.76339 10.8232 3.23661 10.53 3.53L6.06 8L10.53 12.47C10.8232 12.7634 10.8232 13.2366 10.53 13.53C10.2366 13.8232 9.76339 13.8232 9.47 13.53L4.47 8.53C4.17661 8.23661 4.17661 7.76339 4.47 7.47L9.47 2.47C9.76339 2.17661 10.2366 2.17661 10.53 2.47Z"
        fill="#fff"
      />
    </svg>
    <svg
      v-else-if="platform == PlatformEnum.Windows"
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M10.53 2.47C10.8232 2.76339 10.8232 3.23661 10.53 3.53L6.06 8L10.53 12.47C10.8232 12.7634 10.8232 13.2366 10.53 13.53C10.2366 13.8232 9.76339 13.8232 9.47 13.53L4.47 8.53C4.17661 8.23661 4.17661 7.76339 4.47 7.47L9.47 2.47C9.76339 2.17661 10.2366 2.17661 10.53 2.47Z"
        fill="#fff"
      />
    </svg>
    <svg
      v-else
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M10.53 2.47C10.8232 2.76339 10.8232 3.23661 10.53 3.53L6.06 8L10.53 12.47C10.8232 12.7634 10.8232 13.2366 10.53 13.53C10.2366 13.8232 9.76339 13.8232 9.47 13.53L4.47 8.53C4.17661 8.23661 4.17661 7.76339 4.47 7.47L9.47 2.47C9.76339 2.17661 10.2366 2.17661 10.53 2.47Z"
        fill="#fff"
      />
    </svg>
  </div>
</template>

<script>
import { Platform, PlatformEnum } from "@/platform/platform";

export default {
  computed: {
    PlatformEnum: function () {
      return PlatformEnum;
    },
    platform: function () {
      return Platform();
    },
  },
};
</script>

<style scoped lang="scss">
svg {
  vertical-align: middle;
}
</style>
