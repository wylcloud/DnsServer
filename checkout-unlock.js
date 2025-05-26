// checkout-unlock.js

let body = $response.body;

// 伪装金额（防止为 ¥0 导致按钮无效）
body = body.replace(
  /<div class="price-amount amt" id="totalDueToday">.*?<\/div>/,
  `<div class="price-amount amt" id="totalDueToday">¥680.00CNY</div>`
);

// 插入 JS
body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function() {
      var btn = document.getElementById("checkout");
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("disabled");
        btn.removeAttribute("disabled");
        console.log("✅ 按钮已解除禁用");

        // 触发点击事件
        setTimeout(function() {
          btn.click();
          console.log("✅ 已自动点击按钮");
        }, 500); // 延迟 0.5 秒防止页面还在加载
      }

      // 同时也修正金额显示
      var totalDue = document.getElementById("totalDueToday");
      if (totalDue) {
        totalDue.innerText = "¥680.00CNY";
      }
    });
  </script></body>`
);

$done({ body });
