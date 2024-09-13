<template>
  <div
    class="shimmer-wrapper"
    :style="{ width: width, height: height, borderRadius: borderRadius }"
  >
    <div class="shimmer" />
    <div class="shimmer" />
  </div>
</template>

<script>
export default {
  name: "ShimmerEffect",
  props: {
    width: {
      type: String,
      default: "100%",
    },
    height: {
      type: String,
      default: "100px",
    },
    borderRadius: {
      type: String,
      default: "4px",
    },
  },
};
</script>

<style scoped>
.shimmer-wrapper {
  display: flex;
  flex-direction: row;
  background: rgb(133, 133, 133);
  overflow: hidden;
}

.shimmer {
  position: relative;
  width: 200%;
  height: 100%;
  flex-shrink: 0;
  background: rgb(133, 133, 133);
  background: linear-gradient(
    90deg,
    rgba(133, 133, 133, 1) 20%,
    rgba(34, 34, 34, 0.4) 50%,
    rgba(133, 133, 133, 1) 80%
  );
  animation: shimmer 1.2s infinite;
}

@keyframes shimmer {
  from {
    transform: translateX(-50%);
  }
  to {
    transform: translateX(50%);
  }
}
</style>
