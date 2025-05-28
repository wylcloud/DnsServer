let body = $response.body;

// 替换金额，防止为 0 被禁用
body = body.replace(
  /<div class="price-amount amt" id="totalDueToday">.*?<\/div>/,
  `<div class="price-amount amt" id="totalDueToday">¥680.00CNY</div>`
);

// 插入脚本：只解除按钮禁用，不自动触发点击
body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function() {
      const btn = document.getElementById("checkout");
      if (btn) {
        // 解除禁用状态
        btn.disabled = false;
        btn.classList.remove("disabled");
        btn.removeAttribute("disabled");
        console.log("✅ 按钮已解锁（未自动点击）");

        // 添加监听器用于调试点击是否发生
        btn.addEventListener("click", function() {
          console.log("✅ 用户已点击按钮");
        });
      }

      // 确保金额也在页面加载后显示正确
      const totalDue = document.getElementById("totalDueToday");
      if (totalDue) {
        totalDue.innerText = "¥680.00CNY";
        console.log("✅ 金额已修改");
      }
    });
  </script></body>`
);

$done({ body });
