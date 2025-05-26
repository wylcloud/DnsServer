let body = $response.body;

// 修改金额为非零，防止因金额为0被禁用
body = body.replace(
  /<div class="price-amount amt" id="totalDueToday">.*?<\/div>/,
  `<div class="price-amount amt" id="totalDueToday">¥520.00CNY</div>`
);

// 插入 JS 脚本解除按钮限制
body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function() {
      var btn = document.getElementById("checkout");
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("disabled");
        btn.removeAttribute("disabled");
        console.log("✅ 已解除按钮禁用");

        // 模拟点击事件（可选）
        // btn.click();

        // 如果需要强制触发绑定的 click handler，可用：
        var evt = new MouseEvent("click", {
          bubbles: true,
          cancelable: true,
          view: window
        });
        btn.dispatchEvent(evt);
        console.log("✅ 已触发按钮点击事件");
      }

      // 也可尝试修改隐藏的字段（如购物车金额或数据验证）
      var totalDue = document.getElementById("totalDueToday");
      if (totalDue) {
        totalDue.innerText = "¥520.00CNY";
        console.log("✅ 金额已修改");
      }
    });
  </script></body>`
);

$done({ body });
