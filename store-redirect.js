let body = $response.body;

body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function () {
      console.log("🧭 正在跳转至结账页面...");
      window.open("https://lala.gg/cart.php?a=checkout", "_blank");
    });
  </script></body>`
);

$done({ body });
