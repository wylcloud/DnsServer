let body = $response.body;

// 修改金额
body = body.replace(
  /<div class="price-amount amt" id="totalDueToday">.*?<\/div>/,
  `<div class="price-amount amt" id="totalDueToday">¥680.00CNY</div>`
);

// 插入 JS：延迟解除禁用，保持 UI 状态 & 支持真实点击
body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function() {
      setTimeout(function() {
        const btn = document.getElementById("checkout");
        if (btn) {
          // 先尝试触发原始事件绑定（如果需要）
          const evt = new Event("mouseover", { bubbles: true });
          btn.dispatchEvent(evt);

          // 再解除禁用
          btn.disabled = false;
          btn.removeAttribute("disabled");
          btn.classList.remove("disabled");

          console.log("✅ 已解除禁用状态");

          // 添加 click 调试
          btn.addEventListener("click", () => {
            console.log("✅ 用户点击了按钮");
          });
        }

        const totalDue = document.getElementById("totalDueToday");
        if (totalDue) {
          totalDue.innerText = "¥680.00CNY";
          console.log("✅ 金额已更新");
        }
      }, 100); // 延迟 100ms 让页面绑定逻辑先跑完
    });
  </script></body>`
);

$done({ body });
