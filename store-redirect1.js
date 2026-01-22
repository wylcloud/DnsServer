let body = $response.body;

body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function () {
  let btn = document.createElement("button");
  btn.style.position = "fixed";
  btn.style.opacity = 0;
  btn.style.pointerEvents = "none";
  document.body.appendChild(btn);

  btn.addEventListener("click", function() {
    window.open("https://app.kaze.network/cart.php?a=checkout", "_blank");
  });

  // 模拟用户点击
  btn.click();
});

  </script></body>`
);

$done({ body });
