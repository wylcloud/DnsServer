let body = $response.body;

// 修改金额为非零，防止因金额为0被禁用
body = body.replace(
  /<div class="price-amount amt" id="totalDueToday">.*?<\/div>/,
  `<div class="price-amount amt" id="totalDueToday">¥680.00CNY</div>`
);

// 插入 JS 脚本：等待事件绑定完成后自动触发点击
body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function() {
      var btn = document.getElementById("checkout");
      if (btn) {
        // 解除禁用状态
        btn.disabled = false;
        btn.classList.remove("disabled");
        btn.removeAttribute("disabled");
        console.log("✅ 已解除按钮禁用");

        // 修复视觉动画：确保 <i> 可见，loader 是隐藏的
        var icon = btn.querySelector("span > i");
        if (icon) icon.classList.remove("invisible");

        var loader = btn.querySelector(".loader-button");
        if (loader) loader.classList.add("hidden");

        // 模拟真实点击（自动触发原生事件）
        setTimeout(() => {
          var evt = new MouseEvent("click", {
            bubbles: true,
            cancelable: true,
            view: window
          });
          btn.dispatchEvent(evt);
          console.log("✅ 已自动触发点击事件");
        }, 300); // 给页面绑定事件留出足够时间

        // 同时更新金额字段文本
        var totalDue = document.getElementById("totalDueToday");
        if (totalDue) {
          totalDue.innerText = "¥680.00CNY";
          console.log("✅ 金额已修改");
        }
      }
    });
  </script></body>`
);

$done({ body });
