let body = $response.body;

body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function () {
  let a = document.createElement("a");
  a.href = "https://app.kaze.network/cart.php?a=checkout";
  a.target = "_blank";
  document.body.appendChild(a);

  // 尝试触发点击
  a.click();
});

  // 模拟用户点击
  btn.click();
});

  </script></body>`
);

$done({ body });
