// checkout-unlock.js

let body = $response.body;

// 插入一段脚本到页面中，让结账按钮立即变为可用
body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function() {
      var btn = document.getElementById("checkout");
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("disabled"); // 如果有样式控制，也移除
        console.log("结账按钮已解除禁用");
      }
    });
  </script></body>`
);

$done({ body });
